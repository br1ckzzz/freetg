"""Ephemeral Multi-IP / Multi-Port Cloudflare Worker Carousel.

Defeats TSPU's per-TCP-connection ~8-packet / ~16KB freeze on Cloudflare subnets
by mapping stateful MTProto sessions onto stateless HTTP /api calls across
short-lived, pre-warmed TLS/WebSocket sockets rotated after <= 4 requests or
<= 8KB TX / <= 12KB RX.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import random
import socket as _socket
import ssl
import struct
import time
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

log = logging.getLogger("freetg.carousel")

DC_DEFAULT_IPS: Dict[int, str] = {
    1: "149.154.175.50",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "149.154.171.5",
    203: "91.105.192.100",
}

DC_TEST_IPS: Dict[int, str] = {
    1: "149.154.175.10",
    2: "149.154.167.40",
    3: "149.154.175.117",
}

CF_ANYCAST_IPS: Tuple[str, ...] = (
    "162.159.152.4",
    "162.159.135.42",
    "104.18.32.47",
    "141.101.90.96",
    "104.17.112.188",
    "104.21.61.51",
    "172.67.206.124",
)

CF_FALLBACK_DOMAINS: Tuple[str, ...] = (
    "lovetrue.co.uk",
    "pclead.co.uk",
    "offshor.co.uk",
    "cakeisalie.co.uk",
    "noskomnadzor.co.uk",
    "sorokdva.co.uk",
    "pyatdesyatdva.co.uk",
    "kartoshka.co.uk",
    "sorokodin.co.uk",
    "pyatdesyatodin.co.uk",
    "notelega.co.uk",
    "ebally.co.uk",
    "nebally.co.uk",
    "havegreatday.co.uk",
    "pomogite.co.uk",
    "fixtelega.co.uk",
    "sadnews.co.uk",
    "onedaychamp.co.uk",
    "stopblocking.co.uk",
    "nothingthere.co.uk",
)
CF_PUBLIC_DOMAINS = CF_FALLBACK_DOMAINS
CF_PUBLIC_DOMAINS_URL = (
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"
)

CF_HTTPS_PORTS: Tuple[int, ...] = (443,)

MAX_REQS_PER_SOCKET = 4
MAX_TX_BYTES_PER_SOCKET = 8192
MAX_RX_BYTES_PER_SOCKET = 12288
MAX_SOCKET_AGE_SECONDS = 25.0
MAX_IDLE_STREAM_AGE = 45.0
STREAM_READ_TIMEOUT = 120.0

CONNECT_TIMEOUT = 3.0
IO_TIMEOUT = 20.0
ENDPOINT_COOLDOWN_SECONDS = 30.0
CF_DOMAIN_COOLDOWN_SECONDS = 60.0
DEFAULT_POOL_SIZE_PER_DC = 3

_PUBLIC_DOMAINS_CACHE: List[str] = list(CF_FALLBACK_DOMAINS)
_PUBLIC_DOMAINS_LAST_FETCH: float = 0.0
_PUBLIC_DOMAINS_TTL = 6 * 3600.0
_PUBLIC_DOMAINS_FETCHING = False


def _decode_cfproxy_entry(entry: str) -> str:
    """Decode Flowseal's Caesar-shifted .com -> .co.uk entry or normalize a plain hostname."""
    s = (entry or "").strip().lower()
    if not s or s.startswith("#") or "." not in s:
        return ""
    if s.endswith(".com"):
        p = s[:-4]
        n = sum(c.isalpha() for c in p)
        if n > 0:
            decoded = "".join(
                chr((ord(c) - (97 if c > "`" else 65) - n) % 26 + (97 if c > "`" else 65))
                if c.isalpha()
                else c
                for c in p
            )
            return decoded + ".co.uk"
    return s


def _fetch_remote_public_domains_sync() -> List[str]:
    req = urllib.request.Request(
        CF_PUBLIC_DOMAINS_URL,
        headers={"User-Agent": "FreeTG/0.2.2"},
    )
    with urllib.request.urlopen(req, timeout=6.0) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    parsed: List[str] = []
    seen: Set[str] = set()
    for line in raw.splitlines():
        dom = _decode_cfproxy_entry(line)
        if dom and dom not in seen:
            seen.add(dom)
            parsed.append(dom)
    return parsed


async def refresh_public_cf_domains() -> List[str]:
    """Refresh the built-in public CF domain pool non-blockingly from GitHub."""
    global _PUBLIC_DOMAINS_LAST_FETCH, _PUBLIC_DOMAINS_FETCHING
    now = time.monotonic()
    if _PUBLIC_DOMAINS_LAST_FETCH > 0 and (now - _PUBLIC_DOMAINS_LAST_FETCH) < _PUBLIC_DOMAINS_TTL:
        return list(_PUBLIC_DOMAINS_CACHE)
    if _PUBLIC_DOMAINS_FETCHING:
        return list(_PUBLIC_DOMAINS_CACHE)
    _PUBLIC_DOMAINS_FETCHING = True
    try:
        fetched = await asyncio.to_thread(_fetch_remote_public_domains_sync)
        merged: List[str] = []
        seen: Set[str] = set()
        for dom in [*fetched, *CF_FALLBACK_DOMAINS]:
            if dom and dom not in seen:
                seen.add(dom)
                merged.append(dom)
        if merged:
            _PUBLIC_DOMAINS_CACHE[:] = merged
            _PUBLIC_DOMAINS_LAST_FETCH = time.monotonic()
            log.debug("Refreshed public CF domain pool (%d domains)", len(merged))
    except Exception as exc:
        log.debug("Public CF domain pool refresh skipped: %r", exc)
    finally:
        _PUBLIC_DOMAINS_FETCHING = False
    return list(_PUBLIC_DOMAINS_CACHE)

_OP_CONT = 0x0
_OP_TEXT = 0x1
_OP_BINARY = 0x2
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA
_MAX_WS_FRAME = 16 * 1024 * 1024
_XOR_TABLES = tuple(bytes(v ^ k for v in range(256)) for k in range(256))


class WorkerRateLimitError(ConnectionError):
    """Raised when the Cloudflare Worker returns HTTP 429."""


class UpstreamTransportError(ConnectionError):
    """Raised when Telegram DC /api returns an HTTP transport error code."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


class UpstreamHttpRejectError(ConnectionError):
    """Raised when the CF/Worker endpoint responds with non-101 HTTP status."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


@dataclass
class CarouselStats:
    sockets_opened: int = 0
    sockets_rotated: int = 0
    sockets_failed: int = 0
    requests_ok: int = 0
    requests_retried: int = 0
    requests_failed: int = 0
    bytes_tx: int = 0
    bytes_rx: int = 0
    v2_slices_fetched: int = 0


def _xor_mask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    n = len(data)
    if n >= 512:
        buf = bytearray(data)
        for off in range(4):
            buf[off::4] = buf[off::4].translate(_XOR_TABLES[mask[off]])
        return bytes(buf)
    rep = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(rep, "big")).to_bytes(n, "big")


def _build_ws_frame(opcode: int, data: bytes) -> bytes:
    mask = os.urandom(4)
    masked = _xor_mask(data, mask)
    fb = 0x80 | opcode
    n = len(data)
    if n < 126:
        return struct.pack(">BB4s", fb, 0x80 | n, mask) + masked
    if n < 65536:
        return struct.pack(">BBH4s", fb, 0x80 | 126, n, mask) + masked
    return struct.pack(">BBQ4s", fb, 0x80 | 127, n, mask) + masked


def _set_tcp_nodelay(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    for opt in (_socket.SO_SNDBUF, _socket.SO_RCVBUF):
        try:
            sock.setsockopt(_socket.SOL_SOCKET, opt, 262144)
        except (OSError, AttributeError):
            pass


def _create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    try:
        ctx.set_ecdh_curve("X25519")
    except Exception:
        pass
    return ctx


async def _read_http_headers(reader: asyncio.StreamReader, timeout: float) -> Tuple[int, Dict[str, str], bytes]:
    """Read HTTP/1.x status line and headers from an asyncio StreamReader."""
    buf = bytearray()
    while True:
        idx = buf.find(b"\r\n\r\n")
        if idx != -1:
            hdr_raw = bytes(buf[:idx])
            leftover = bytes(buf[idx + 4 :])
            break
        if len(buf) > 32768:
            raise ConnectionError("HTTP response header exceeded 32KB")
        chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        if not chunk:
            raise ConnectionError("EOF reading HTTP headers")
        buf.extend(chunk)

    lines = hdr_raw.decode("utf-8", errors="replace").split("\r\n")
    parts = lines[0].split(" ", 2)
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, leftover


class _FragmentedTlsReader:
    """Async reader adapter over an ssl.SSLObject + MemoryBIO."""

    def __init__(self, raw_reader: asyncio.StreamReader, raw_writer: asyncio.StreamWriter,
                 sslobj: ssl.SSLObject, inc: ssl.MemoryBIO, outg: ssl.MemoryBIO,
                 drain_lock: Optional[asyncio.Lock] = None):
        self._raw_r = raw_reader
        self._raw_w = raw_writer
        self._ssl = sslobj
        self._inc = inc
        self._outg = outg
        self._drain_lock = drain_lock or asyncio.Lock()
        self._buf = bytearray()
        self._eof = False

    async def _flush_out(self) -> None:
        async with self._drain_lock:
            data = self._outg.read()
            if data:
                self._raw_w.write(data)
                await self._raw_w.drain()

    async def read(self, n: int = 65536) -> bytes:
        if self._buf:
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out
        if self._eof:
            return b""
        while True:
            try:
                chunk = self._ssl.read(n)
                await self._flush_out()
                return chunk
            except ssl.SSLWantReadError:
                await self._flush_out()
                raw = await self._raw_r.read(16384)
                if not raw:
                    self._eof = True
                    return b""
                self._inc.write(raw)
            except ssl.SSLEOFError:
                self._eof = True
                return b""

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = await self.read(max(4096, n - len(self._buf)))
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(self._buf), n)
            self._buf.extend(chunk)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def at_eof(self) -> bool:
        return self._eof and not self._buf


class _FragmentedTlsWriter:
    """Async writer adapter over an ssl.SSLObject + MemoryBIO."""

    def __init__(self, raw_writer: asyncio.StreamWriter,
                 sslobj: ssl.SSLObject, outg: ssl.MemoryBIO,
                 drain_lock: Optional[asyncio.Lock] = None):
        self._raw_w = raw_writer
        self._ssl = sslobj
        self._outg = outg
        self._drain_lock = drain_lock or asyncio.Lock()
        self._closing = False

    def write(self, data: bytes) -> None:
        if data:
            self._ssl.write(data)

    async def drain(self) -> None:
        async with self._drain_lock:
            data = self._outg.read()
            if data:
                self._raw_w.write(data)
                await self._raw_w.drain()

    def close(self) -> None:
        self._closing = True
        self._raw_w.close()

    def abort(self) -> None:
        self._closing = True
        transport = getattr(self._raw_w, "transport", None)
        if transport is not None:
            transport.abort()
        else:
            self._raw_w.close()

    async def wait_closed(self) -> None:
        await self._raw_w.wait_closed()

    def is_closing(self) -> bool:
        return self._closing or self._raw_w.is_closing()


def _abort_writer(writer) -> None:
    """Immediately abort an underlying transport so failed/timed-out sockets do not linger."""
    try:
        if hasattr(writer, "abort"):
            writer.abort()
            return
        transport = getattr(writer, "transport", None)
        if transport is not None:
            transport.abort()
            return
    except Exception:
        pass
    try:
        writer.close()
    except Exception:
        pass


async def _open_tls_socket(
    ip: str,
    port: int,
    server_hostname: str,
    ssl_ctx: ssl.SSLContext,
    timeout: float,
    frag_tls: bool = False,
):
    """Connect to (ip, port) via TLS, optionally fragmenting TLS ClientHello records."""
    if not frag_tls:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_ctx, server_hostname=server_hostname),
            timeout=timeout,
        )
        _set_tcp_nodelay(writer)
        return reader, writer

    raw_r, raw_w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    _set_tcp_nodelay(raw_w)
    inc = ssl.MemoryBIO()
    outg = ssl.MemoryBIO()
    sslobj = ssl_ctx.wrap_bio(inc, outg, server_hostname=server_hostname)
    try:
        sslobj.do_handshake()
    except ssl.SSLWantReadError:
        pass

    ch = outg.read()
    if ch and ch[0] == 0x16 and len(ch) > 5:
        # Split the single TLS ClientHello record across two TCP segments around SNI.
        # Splitting at the TCP layer preserves a valid TLS record for strict proxies
        # while still breaking up the SNI for DPI/TSPU inspection.
        payload = ch[5:]
        sni_bytes = server_hostname.encode("ascii", errors="ignore")
        sni_pos = payload.find(sni_bytes) if sni_bytes else -1

        cut = 5 + (
            (sni_pos + max(2, len(sni_bytes) // 2))
            if sni_pos >= 0
            else max(2, len(payload) // 2)
        )
        frags: List[bytes] = [ch[:cut], ch[cut:]]

        for i, frag in enumerate(frags):
            raw_w.write(frag)
            await raw_w.drain()
            if i + 1 < len(frags):
                await asyncio.sleep(0.002)
    elif ch:
        raw_w.write(ch)
        await raw_w.drain()

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        try:
            sslobj.do_handshake()
            rem = outg.read()
            if rem:
                raw_w.write(rem)
                await asyncio.wait_for(raw_w.drain(), timeout=max(0.25, deadline - loop.time()))
            break
        except ssl.SSLWantReadError:
            rem = outg.read()
            if rem:
                raw_w.write(rem)
                await asyncio.wait_for(raw_w.drain(), timeout=max(0.25, deadline - loop.time()))
            raw = await asyncio.wait_for(raw_r.read(16384), timeout=max(0.25, deadline - loop.time()))
            if not raw:
                _abort_writer(raw_w)
                raise ConnectionError("EOF during fragmented TLS handshake")
            inc.write(raw)
        except BaseException:
            _abort_writer(raw_w)
            raise

    drain_lock = asyncio.Lock()
    return (
        _FragmentedTlsReader(raw_r, raw_w, sslobj, inc, outg, drain_lock=drain_lock),
        _FragmentedTlsWriter(raw_w, sslobj, outg, drain_lock=drain_lock),
    )


class _BaseWsSocket:
    """Shared WebSocket frame reader/writer with leftover prebuffer support."""

    def __init__(self, reader, writer, leftover: bytes = b""):
        self.reader = reader
        self.writer = writer
        self.created_at = time.monotonic()
        self.bytes_tx = 0
        self.bytes_rx = 0
        self.closed = False
        self._ws_prebuf = bytearray(leftover)
        self._ws_frag = bytearray()

    async def _readexactly_ws(self, n: int, timeout: float) -> bytes:
        while len(self._ws_prebuf) < n:
            chunk = await asyncio.wait_for(self.reader.read(max(4096, n - len(self._ws_prebuf))), timeout=timeout)
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(self._ws_prebuf), n)
            self._ws_prebuf.extend(chunk)
        out = bytes(self._ws_prebuf[:n])
        del self._ws_prebuf[:n]
        return out

    async def _ws_read_frame(self, timeout: float = IO_TIMEOUT) -> Tuple[int, bytes, bool]:
        hdr = await self._readexactly_ws(2, timeout)
        fin = bool(hdr[0] & 0x80)
        opcode = hdr[0] & 0x0F
        length = hdr[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", await self._readexactly_ws(2, timeout))[0]
        elif length == 127:
            length = struct.unpack(">Q", await self._readexactly_ws(8, timeout))[0]
        if length > _MAX_WS_FRAME:
            raise ConnectionError(f"WS frame too large: {length}")
        if hdr[1] & 0x80:
            mask_key = await self._readexactly_ws(4, timeout)
            payload = await self._readexactly_ws(length, timeout)
            payload = _xor_mask(payload, mask_key)
        else:
            payload = await self._readexactly_ws(length, timeout)
        self.bytes_rx += 2 + length
        return opcode, payload, fin

    async def _ws_recv_bytes(self, timeout: float = IO_TIMEOUT) -> Optional[bytes]:
        while not self.closed:
            opcode, payload, fin = await self._ws_read_frame(timeout=timeout)
            if opcode == _OP_CLOSE:
                self.closed = True
                try:
                    self.writer.write(_build_ws_frame(_OP_CLOSE, payload[:2] if payload else b""))
                    await self.writer.drain()
                except Exception:
                    pass
                return None
            if opcode == _OP_PING:
                try:
                    self.writer.write(_build_ws_frame(_OP_PONG, payload))
                    await self.writer.drain()
                except Exception:
                    pass
                continue
            if opcode == _OP_PONG:
                continue
            if opcode in (_OP_CONT, _OP_TEXT, _OP_BINARY):
                if fin and not self._ws_frag:
                    return payload
                self._ws_frag.extend(payload)
                if len(self._ws_frag) > _MAX_WS_FRAME:
                    raise ConnectionError("Fragmented WS message exceeded limit")
                if not fin:
                    continue
                msg = bytes(self._ws_frag)
                self._ws_frag.clear()
                return msg
        return None

    async def send_ws(self, data: bytes, timeout: float = IO_TIMEOUT) -> None:
        if self.closed:
            raise ConnectionError("WebSocket closed")
        frame = _build_ws_frame(_OP_BINARY, data)
        self.writer.write(frame)
        await asyncio.wait_for(self.writer.drain(), timeout=timeout)
        self.bytes_tx += len(frame)

    send_binary = send_ws
    recv_binary = _ws_recv_bytes

    async def send_ws_batch(self, parts: List[bytes], timeout: float = IO_TIMEOUT) -> None:
        if self.closed:
            raise ConnectionError("WebSocket closed")
        total = 0
        for part in parts:
            frame = _build_ws_frame(_OP_BINARY, part)
            self.writer.write(frame)
            total += len(frame)
        await asyncio.wait_for(self.writer.drain(), timeout=timeout)
        self.bytes_tx += total

    async def send_ping(self) -> None:
        if not self.closed:
            self.writer.write(_build_ws_frame(_OP_PING, os.urandom(8)))
            await asyncio.wait_for(self.writer.drain(), timeout=IO_TIMEOUT)

    async def close(self) -> None:
        self.closed = True
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), timeout=1.0)
        except Exception:
            pass


class StreamingWorkerSocket(_BaseWsSocket):
    """Full-duplex WebSocket tunnel to either Cloudflare Worker or CF proxy domain."""

    def __init__(
        self,
        *,
        dc: int,
        dst_ip: str,
        cf_ip: str,
        cf_port: int,
        host: str,
        is_cf_direct: bool,
        reader,
        writer,
        leftover: bytes = b"",
    ):
        super().__init__(reader, writer, leftover=leftover)
        self.dc = dc
        self.dst_ip = dst_ip
        self.cf_ip = cf_ip
        self.cf_port = cf_port
        self.host = host
        self.is_cf_direct = is_cf_direct

    @property
    def endpoint(self) -> Tuple[str, int]:
        return (self.cf_ip, self.cf_port)

    def is_idle_healthy(self) -> bool:
        if self.closed or self.writer.is_closing() or self.reader.at_eof():
            return False
        return (time.monotonic() - self.created_at) < MAX_IDLE_STREAM_AGE

    @classmethod
    async def connect(
        cls,
        *,
        dc: int,
        dst_ip: str,
        cf_ip: str,
        cf_port: int,
        sni_host: str,
        http_host: str,
        path: str,
        is_cf_direct: bool,
        ssl_ctx: ssl.SSLContext,
        frag_tls: bool = False,
        use_tls: bool = True,
        timeout: float = CONNECT_TIMEOUT,
    ) -> "StreamingWorkerSocket":
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        conn_timeout = max(0.25, deadline - loop.time())
        if use_tls:
            reader, writer = await _open_tls_socket(
                cf_ip, cf_port, sni_host, ssl_ctx, conn_timeout, frag_tls=frag_tls
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(cf_ip, cf_port),
                timeout=conn_timeout,
            )
            _set_tcp_nodelay(writer)
        try:
            ws_key = base64.b64encode(os.urandom(16)).decode()
            proto_hdr = "Sec-WebSocket-Protocol: binary\r\n" if is_cf_direct else ""
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {http_host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"{proto_hdr}\r\n"
            ).encode()
            writer.write(req)
            await asyncio.wait_for(writer.drain(), timeout=max(0.25, deadline - loop.time()))
            status, _, leftover = await _read_http_headers(
                reader, max(0.25, deadline - loop.time())
            )
            if status == 429:
                raise WorkerRateLimitError("Cloudflare Worker returned HTTP 429")
            if status != 101:
                raise UpstreamHttpRejectError(status, f"Stream WS upgrade failed with HTTP {status}")
            return cls(
                dc=dc,
                dst_ip=dst_ip,
                cf_ip=cf_ip,
                cf_port=cf_port,
                host=http_host,
                is_cf_direct=is_cf_direct,
                reader=reader,
                writer=writer,
                leftover=leftover,
            )
        except BaseException:
            _abort_writer(writer)
            raise

    async def recv_ws(self, timeout: float = STREAM_READ_TIMEOUT) -> Optional[bytes]:
        return await self._ws_recv_bytes(timeout=timeout)


class EphemeralWorkerSocket(_BaseWsSocket):
    """Single short-lived TLS socket to a Cloudflare edge node (WS or HTTP v2)."""

    def __init__(
        self,
        *,
        dc: int,
        dst_ip: str,
        cf_ip: str,
        cf_port: int,
        worker_domain: str,
        mode: str,
        reader,
        writer,
        leftover: bytes = b"",
    ):
        super().__init__(reader, writer, leftover=leftover if mode == "v1" else b"")
        self.dc = dc
        self.dst_ip = dst_ip
        self.cf_ip = cf_ip
        self.cf_port = cf_port
        self.worker_domain = worker_domain
        self.mode = mode  # "v1" (WS /apiws) or "v2" (HTTP /v2/sync)
        self.requests_sent = 0
        self._inner_buf = bytearray()

    @property
    def endpoint(self) -> Tuple[str, int]:
        return (self.cf_ip, self.cf_port)

    def can_reuse(self) -> bool:
        if self.closed or self.writer.is_closing() or self.reader.at_eof():
            return False
        if (time.monotonic() - self.created_at) >= MAX_SOCKET_AGE_SECONDS:
            return False
        if self.requests_sent >= MAX_REQS_PER_SOCKET:
            return False
        if self.bytes_tx >= MAX_TX_BYTES_PER_SOCKET:
            return False
        if self.bytes_rx >= MAX_RX_BYTES_PER_SOCKET:
            return False
        return True

    @classmethod
    async def connect(
        cls,
        *,
        dc: int,
        dst_ip: str,
        cf_ip: str,
        cf_port: int,
        worker_domain: str,
        mode: str,
        ssl_ctx: ssl.SSLContext,
        frag_tls: bool = False,
        timeout: float = CONNECT_TIMEOUT,
    ) -> "EphemeralWorkerSocket":
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        reader, writer = await _open_tls_socket(
            cf_ip, cf_port, worker_domain, ssl_ctx, max(0.25, deadline - loop.time()), frag_tls=frag_tls
        )
        try:
            if mode == "v1":
                ws_key = base64.b64encode(os.urandom(16)).decode()
                req = (
                    f"GET /apiws?dst={dst_ip}&dc={dc} HTTP/1.1\r\n"
                    f"Host: {worker_domain}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode()
                writer.write(req)
                await asyncio.wait_for(writer.drain(), timeout=max(0.25, deadline - loop.time()))
                status, _, leftover = await _read_http_headers(
                    reader, max(0.25, deadline - loop.time())
                )
                if status == 429:
                    raise WorkerRateLimitError("Cloudflare Worker returned HTTP 429")
                if status != 101:
                    raise ConnectionError(f"Worker WS upgrade failed with HTTP {status}")
            else:
                leftover = b""
            return cls(
                dc=dc,
                dst_ip=dst_ip,
                cf_ip=cf_ip,
                cf_port=cf_port,
                worker_domain=worker_domain,
                mode=mode,
                reader=reader,
                writer=writer,
                leftover=leftover,
            )
        except BaseException:
            _abort_writer(writer)
            raise

    async def _fill_inner_buf(self) -> bool:
        chunk = await self._ws_recv_bytes()
        if chunk is None:
            return False
        self._inner_buf.extend(chunk)
        return True

    async def _read_inner_http_response(self) -> Tuple[int, Dict[str, str], bytes]:
        while True:
            idx = self._inner_buf.find(b"\r\n\r\n")
            if idx != -1:
                hdr_bytes = bytes(self._inner_buf[:idx])
                del self._inner_buf[: idx + 4]
                break
            if len(self._inner_buf) > 32768:
                raise ConnectionError("Inner HTTP header too large")
            if not await self._fill_inner_buf():
                raise ConnectionError("Upstream WS closed before HTTP headers")

        lines = hdr_bytes.decode("utf-8", errors="replace").split("\r\n")
        parts = lines[0].split(" ", 2)
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if "content-length" in headers:
            need = int(headers["content-length"])
            while len(self._inner_buf) < need:
                if not await self._fill_inner_buf():
                    raise ConnectionError("Upstream WS closed mid Content-Length body")
            body = bytes(self._inner_buf[:need])
            del self._inner_buf[:need]
            return status, headers, body

        if "chunked" in headers.get("transfer-encoding", "").lower():
            out = bytearray()
            while True:
                while b"\r\n" not in self._inner_buf:
                    if not await self._fill_inner_buf():
                        raise ConnectionError("Upstream WS closed reading chunk size")
                nl = self._inner_buf.find(b"\r\n")
                sz_line = bytes(self._inner_buf[:nl]).split(b";", 1)[0].strip()
                del self._inner_buf[: nl + 2]
                chunk_len = int(sz_line, 16)
                if chunk_len == 0:
                    while len(self._inner_buf) < 2:
                        if not await self._fill_inner_buf():
                            break
                    if len(self._inner_buf) >= 2:
                        del self._inner_buf[:2]
                    return status, headers, bytes(out)
                while len(self._inner_buf) < chunk_len + 2:
                    if not await self._fill_inner_buf():
                        raise ConnectionError("Upstream WS closed reading chunk payload")
                out.extend(self._inner_buf[:chunk_len])
                del self._inner_buf[: chunk_len + 2]

        # Connection: close fallback
        while await self._fill_inner_buf():
            pass
        body = bytes(self._inner_buf)
        self._inner_buf.clear()
        return status, headers, body

    async def post_mtproto_v1(self, mt_body: bytes) -> bytes:
        """Send one MTProto packet as HTTP POST /api inside the Worker WS tunnel."""
        http_req = (
            f"POST /api HTTP/1.1\r\n"
            f"Host: {self.dst_ip}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(mt_body)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode() + mt_body
        frame = _build_ws_frame(_OP_BINARY, http_req)
        self.writer.write(frame)
        await asyncio.wait_for(self.writer.drain(), timeout=IO_TIMEOUT)
        self.requests_sent += 1
        self.bytes_tx += len(frame)

        status, headers, body = await self._read_inner_http_response()
        if headers.get("connection", "").lower() == "close":
            self.closed = True
        if status in (403, 404, 429, 444):
            raise UpstreamTransportError(-status, f"HTTP {status} from DC{self.dc}")
        if status != 200:
            raise ConnectionError(f"Unexpected HTTP {status} from DC{self.dc}")
        if len(body) == 4:
            code, = struct.unpack("<i", body)
            if code < 0:
                raise UpstreamTransportError(code, f"MTProto error {code} from DC{self.dc}")
        if body and len(body) % 4 != 0:
            raise ValueError(f"Unaligned MTProto reply length: {len(body)}")
        return body

    async def post_mtproto_v2(self, mt_body: bytes) -> Tuple[int, Dict[str, str], bytes]:
        """Send one MTProto packet via Worker /v2/sync HTTP endpoint."""
        req = (
            f"POST /v2/sync?dst={self.dst_ip} HTTP/1.1\r\n"
            f"Host: {self.worker_domain}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(mt_body)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode() + mt_body
        self.writer.write(req)
        await asyncio.wait_for(self.writer.drain(), timeout=IO_TIMEOUT)
        self.requests_sent += 1
        self.bytes_tx += len(req)
        return await self._read_direct_http_response()

    async def get_v2_slice(self, slice_id: str, offset: int, length: int) -> bytes:
        req = (
            f"GET /v2/slice?id={slice_id}&off={offset}&len={length} HTTP/1.1\r\n"
            f"Host: {self.worker_domain}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode()
        self.writer.write(req)
        await asyncio.wait_for(self.writer.drain(), timeout=IO_TIMEOUT)
        self.requests_sent += 1
        self.bytes_tx += len(req)
        status, _, body = await self._read_direct_http_response()
        if status != 200:
            raise ConnectionError(f"Worker /v2/slice HTTP {status}")
        return body

    async def _read_direct_http_response(self) -> Tuple[int, Dict[str, str], bytes]:
        buf = bytearray(self._inner_buf)
        self._inner_buf.clear()
        while True:
            idx = buf.find(b"\r\n\r\n")
            if idx != -1:
                hdr_raw = bytes(buf[:idx])
                del buf[: idx + 4]
                break
            chunk = await asyncio.wait_for(self.reader.read(8192), timeout=IO_TIMEOUT)
            if not chunk:
                raise ConnectionError("EOF reading direct HTTP headers")
            self.bytes_rx += len(chunk)
            buf.extend(chunk)

        lines = hdr_raw.decode("utf-8", errors="replace").split("\r\n")
        parts = lines[0].split(" ", 2)
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if headers.get("connection", "").lower() == "close":
            self.closed = True

        if "content-length" in headers:
            need = int(headers["content-length"])
            while len(buf) < need:
                chunk = await asyncio.wait_for(self.reader.read(8192), timeout=IO_TIMEOUT)
                if not chunk:
                    raise ConnectionError("EOF reading direct Content-Length body")
                self.bytes_rx += len(chunk)
                buf.extend(chunk)
            body = bytes(buf[:need])
            self._inner_buf.extend(buf[need:])
            return status, headers, body

        if "chunked" in headers.get("transfer-encoding", "").lower():
            out = bytearray()
            while True:
                while b"\r\n" not in buf:
                    chunk = await asyncio.wait_for(self.reader.read(8192), timeout=IO_TIMEOUT)
                    if not chunk:
                        raise ConnectionError("EOF reading direct chunked size")
                    self.bytes_rx += len(chunk)
                    buf.extend(chunk)
                nl = buf.find(b"\r\n")
                sz = int(bytes(buf[:nl]).split(b";", 1)[0].strip(), 16)
                del buf[: nl + 2]
                if sz == 0:
                    while len(buf) < 2:
                        chunk = await asyncio.wait_for(self.reader.read(256), timeout=IO_TIMEOUT)
                        if not chunk:
                            break
                        self.bytes_rx += len(chunk)
                        buf.extend(chunk)
                    if len(buf) >= 2:
                        del buf[:2]
                    self._inner_buf.extend(buf)
                    return status, headers, bytes(out)
                while len(buf) < sz + 2:
                    chunk = await asyncio.wait_for(self.reader.read(8192), timeout=IO_TIMEOUT)
                    if not chunk:
                        raise ConnectionError("EOF reading direct chunked payload")
                    self.bytes_rx += len(chunk)
                    buf.extend(chunk)
                out.extend(buf[:sz])
                del buf[: sz + 2]

        while True:
            chunk = await asyncio.wait_for(self.reader.read(8192), timeout=IO_TIMEOUT)
            if not chunk:
                break
            self.bytes_rx += len(chunk)
            buf.extend(chunk)
        self.closed = True
        return status, headers, bytes(buf)

    async def close(self) -> None:
        self.closed = True
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), timeout=1.0)
        except Exception:
            pass


class DcCarouselPool:
    """Manages pre-warmed ephemeral Worker sockets across CF Anycast IPs & ports."""

    def __init__(
        self,
        worker_domain: str = "",
        *,
        mode: str = "auto",
        pool_size: int = DEFAULT_POOL_SIZE_PER_DC,
        frag_tls: bool = False,
        prefer_port80_cf: bool = False,
        allow_port80_fallback: bool = True,
        cf_ips: Optional[List[str]] = None,
        cf_ports: Optional[List[int]] = None,
    ):
        parsed_workers: List[str] = []
        seen_w: Set[str] = set()
        for tok in (worker_domain or "").replace(",", " ").replace(";", " ").split():
            d = tok.strip()
            low = d.lower()
            if low.startswith("https://"):
                d = d[8:]
            elif low.startswith("http://"):
                d = d[7:]
            d = d.split("/", 1)[0].strip().rstrip(".")
            if d and "." in d and d.lower() not in seen_w:
                seen_w.add(d.lower())
                parsed_workers.append(d)

        self.worker_domains: List[str] = parsed_workers
        self.worker_domain = parsed_workers[0] if parsed_workers else ""
        self.requested_mode = mode
        self.active_mode = "v1" if mode == "v1" else ("v2" if mode == "v2" else "v1")
        self.pool_size = max(1, pool_size)
        self.frag_tls = frag_tls
        self.prefer_port80_cf = prefer_port80_cf
        self.allow_port80_fallback = allow_port80_fallback
        self.ssl_ctx = _create_ssl_context()
        self.stats = CarouselStats()

        ips = list(cf_ips) if cf_ips else list(CF_ANYCAST_IPS)
        ports = list(cf_ports) if cf_ports else list(CF_HTTPS_PORTS)
        self._endpoints: List[Tuple[str, int]] = [(ip, port) for port in ports for ip in ips]
        self._endpoint_cooldown: Dict[Tuple[str, int], float] = {}
        self._endpoint_rtt: Dict[Tuple[str, int], float] = {}
        self._cf_domain_cooldown: Dict[str, float] = {}
        self._worker_cooldown: Dict[str, float] = {}
        self._worker_no_port80: Set[str] = set()
        self._tls_timeout_streak = 0
        self._rr_cursor = 0
        self._cf_domain_cursor = 0

        self._idle: Dict[Tuple[int, bool], Deque[EphemeralWorkerSocket]] = {}
        self._refilling: Set[Tuple[int, bool]] = set()
        self._stream_idle: Dict[Tuple[int, bool], Deque[StreamingWorkerSocket]] = {}
        self._stream_refilling: Set[Tuple[int, bool]] = set()
        self._refill_tasks: Set[asyncio.Task] = set()
        self._closed = False

    @property
    def has_custom_worker(self) -> bool:
        return bool(self.worker_domains)

    @property
    def public_domains(self) -> List[str]:
        return list(_PUBLIC_DOMAINS_CACHE) if _PUBLIC_DOMAINS_CACHE else list(CF_FALLBACK_DOMAINS)

    def resolve_dc_ip(self, dc: int, is_test_dc: bool) -> str:
        table = DC_TEST_IPS if is_test_dc else DC_DEFAULT_IPS
        if dc in table:
            return table[dc]
        return DC_DEFAULT_IPS[2]

    async def initialize(self) -> None:
        """Refresh public CF domains in background and probe Worker capabilities if set."""
        refresh_task = asyncio.create_task(refresh_public_cf_domains())
        self._refill_tasks.add(refresh_task)
        refresh_task.add_done_callback(self._refill_tasks.discard)

        if self.has_custom_worker:
            try:
                loop = asyncio.get_running_loop()
                infos = await loop.getaddrinfo(self.worker_domain, 443, family=_socket.AF_INET)
                resolved = [info[4][0] for info in infos]
                known = {ip for ip, _ in self._endpoints}
                for ip in resolved:
                    if ip not in known:
                        for port in CF_HTTPS_PORTS:
                            self._endpoints.append((ip, port))
            except Exception as exc:
                log.debug("DNS resolution for %s skipped: %r", self.worker_domain, exc)

        if not self.frag_tls and not self.prefer_port80_cf:
            probe_eps = list(self._endpoints[:3])
            if not await self._check_tls_reachable(frag_tls=False, endpoints=probe_eps):
                if await self._check_tls_reachable(frag_tls=True, endpoints=probe_eps):
                    self.frag_tls = True
                    log.info(
                        "Auto-enabled TLS ClientHello fragmentation for %s",
                        self.worker_domain or "public CF pool",
                    )

        if not self.has_custom_worker:
            self.active_mode = "v1"
            log.info(
                "Using built-in public CF pool (%d domains, mode=V1)",
                len(self.public_domains),
            )
        elif self.requested_mode in ("auto", "v2"):
            v2_ok = await self._probe_v2_health()
            if self.requested_mode == "v2" and not v2_ok:
                self.active_mode = "v1"
                log.warning(
                    "Worker %s does not expose /v2/health; falling back to V1",
                    self.worker_domain,
                )
            else:
                self.active_mode = "v2" if v2_ok else "v1"
                log.info("Auto-detected Worker mode: %s", self.active_mode.upper())
        else:
            self.active_mode = self.requested_mode
            log.info("Configured Worker mode: %s", self.active_mode.upper())

        # Pre-warm streaming WebSockets for primary DCs (DC2, DC4, DC203)
        for dc in (2, 4, 203):
            self._schedule_stream_refill(dc, False)

    async def _check_tls_reachable(
        self, *, frag_tls: bool, endpoints: Optional[List[Tuple[str, int]]] = None
    ) -> bool:
        sni_host = self.worker_domain if self.has_custom_worker else f"kws2.{self.public_domains[0]}"
        eps = endpoints if endpoints is not None else list(self._endpoints[:3])
        for ip, port in eps:
            try:
                reader, writer = await _open_tls_socket(
                    ip, port, sni_host, self.ssl_ctx, 2.5, frag_tls=frag_tls
                )
                writer.close()
                return True
            except Exception:
                continue
        return False

    async def probe_deep_stream(
        self, dc: int = 2, target_bytes: int = 22000
    ) -> Tuple[bool, int, Optional[str]]:
        """Verify a single WS tunnel transfers >22KB without TSPU 16-19KB freeze."""
        from .crypto import PROTO_TAG_SECURE, generate_relay_init

        excluded: Set[Tuple[str, int]] = set()
        last_err: Optional[str] = None
        for attempt in range(2):
            sock = await self._connect_stream_socket(dc, False, exclude=excluded)
            sent = 0
            seq = 0
            try:
                init_bytes, tg_enc, tg_dec = generate_relay_init(PROTO_TAG_SECURE, dc)
                if sock.is_cf_direct:
                    await sock.send_ws(init_bytes)
                base_ts = int(time.time() * (2**32)) & ~3
                while sent < target_bytes:
                    nonce = os.urandom(16)
                    msg_id = base_ts + seq * 4
                    seq += 1
                    req_body = struct.pack("<QQII", 0, msg_id, 20, 0xBE7E8EF1) + nonce
                    pad = os.urandom(252)
                    framed = struct.pack("<I", len(req_body) + len(pad)) + req_body + pad
                    payload = tg_enc.update(framed)
                    if seq == 1 and not sock.is_cf_direct:
                        await sock.send_ws(init_bytes + payload)
                    else:
                        await sock.send_ws(payload)
                    sent += len(framed)
                    chunk = await sock.recv_ws(timeout=4.0)
                    if not chunk:
                        if seq == 1 and attempt == 0:
                            excluded.add(sock.endpoint)
                            last_err = "соединение закрыто на первом пакете"
                            break
                        return False, sent, f"соединение закрыто на {max(1, sent // 1024)} КБ"
                    plain = tg_dec.update(chunk)
                    if b"\x63\x24\x16\x05" not in plain:
                        return False, sent, f"неожиданный ответ на шаге {seq}"
                else:
                    return True, sent, None
            except asyncio.TimeoutError:
                if seq == 1 and attempt == 0:
                    excluded.add(sock.endpoint)
                    self._mark_endpoint_failed(sock.endpoint)
                    last_err = "таймаут первого ответа DC"
                    continue
                if seq <= 1:
                    return False, sent, "таймаут первого ответа DC"
                return False, sent, f"заморозка ТСПУ на {sent // 1024} КБ"
            except Exception as exc:
                if seq <= 1 and attempt == 0:
                    excluded.add(sock.endpoint)
                    last_err = str(exc)
                    continue
                return False, sent, str(exc)
            finally:
                await sock.close()

        return False, 0, last_err or "нет ответа от DC"

    async def _probe_v2_health(self) -> bool:
        ip, port = self._pick_endpoint()
        try:
            reader, writer = await _open_tls_socket(
                ip, port, self.worker_domain, self.ssl_ctx, 3.0, frag_tls=self.frag_tls
            )
            try:
                req = (
                    f"GET /v2/health HTTP/1.1\r\n"
                    f"Host: {self.worker_domain}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                writer.write(req)
                await writer.drain()
                status, _, _ = await _read_http_headers(reader, 3.0)
                return status == 200
            finally:
                writer.close()
        except Exception:
            return False

    def _pick_endpoint(self, exclude: Optional[Set[Tuple[str, int]]] = None) -> Tuple[str, int]:
        now = time.monotonic()
        candidates = [
            ep for ep in self._endpoints
            if now >= self._endpoint_cooldown.get(ep, 0.0) and (not exclude or ep not in exclude)
        ]
        if not candidates:
            candidates = list(self._endpoints)
        # Prefer endpoints with known fast RTT, plus occasional exploration across ports/IPs.
        known_fast = [ep for ep in candidates if ep in self._endpoint_rtt]
        if known_fast and random.random() < 0.75:
            known_fast.sort(key=lambda ep: self._endpoint_rtt[ep])
            top = known_fast[: min(6, len(known_fast))]
            return random.choice(top)
        ep = candidates[self._rr_cursor % len(candidates)]
        self._rr_cursor += 1
        return ep

    def _mark_endpoint_failed(self, ep: Tuple[str, int]) -> None:
        self._endpoint_cooldown[ep] = time.monotonic() + ENDPOINT_COOLDOWN_SECONDS
        self._endpoint_rtt.pop(ep, None)

    def _mark_endpoint_ok(self, ep: Tuple[str, int], rtt: float) -> None:
        self._endpoint_cooldown.pop(ep, None)
        prev = self._endpoint_rtt.get(ep)
        self._endpoint_rtt[ep] = rtt if prev is None else (prev * 0.6 + rtt * 0.4)

    def _mark_worker_rate_limited(self, domain: str) -> None:
        """Put a rate-limited custom Worker domain (HTTP 429) on cooldown until UTC midnight."""
        key = (domain or "").strip().lower()
        if not key:
            return
        now_mono = time.monotonic()
        if self._worker_cooldown.get(key, 0.0) > now_mono:
            return
        secs_until_utc_midnight = max(60.0, 86400.0 - (time.time() % 86400.0))
        self._worker_cooldown[key] = now_mono + secs_until_utc_midnight
        log.warning(
            "Cloudflare Worker %s hit HTTP 429 daily limit; pausing for %.0fs until 00:00 UTC",
            key,
            secs_until_utc_midnight,
        )

    def _available_worker_domains(self) -> List[str]:
        now = time.monotonic()
        return [
            d for d in self.worker_domains
            if now >= self._worker_cooldown.get(d.lower(), 0.0)
        ]

    async def _connect_socket(self, dc: int, is_test_dc: bool,
                              exclude: Optional[Set[Tuple[str, int]]] = None) -> EphemeralWorkerSocket:
        if not self.has_custom_worker:
            raise ConnectionError("No custom Worker configured for stateless /api fallback")
        dst_ip = self.resolve_dc_ip(dc, is_test_dc)
        last_exc: Optional[Exception] = None
        tried: Set[Tuple[str, int]] = set(exclude or ())
        avail_workers = self._available_worker_domains()
        if not avail_workers:
            raise WorkerRateLimitError("All custom Cloudflare Workers are in HTTP 429 cooldown")
        for attempt in range(max(4, len(avail_workers))):
            avail_workers = self._available_worker_domains()
            if not avail_workers:
                raise WorkerRateLimitError("All custom Cloudflare Workers are in HTTP 429 cooldown")
            w_dom = avail_workers[attempt % len(avail_workers)]
            ep = self._pick_endpoint(exclude=tried)
            tried.add(ep)
            t0 = time.monotonic()
            try:
                sock = await EphemeralWorkerSocket.connect(
                    dc=dc,
                    dst_ip=dst_ip,
                    cf_ip=ep[0],
                    cf_port=ep[1],
                    worker_domain=w_dom,
                    mode=self.active_mode,
                    ssl_ctx=self.ssl_ctx,
                    frag_tls=self.frag_tls,
                )
                self._mark_endpoint_ok(ep, time.monotonic() - t0)
                self.stats.sockets_opened += 1
                return sock
            except WorkerRateLimitError as exc:
                self.stats.sockets_failed += 1
                self._mark_worker_rate_limited(w_dom)
                last_exc = exc
                if not self._available_worker_domains():
                    raise
            except Exception as exc:
                self.stats.sockets_failed += 1
                self._mark_endpoint_failed(ep)
                last_exc = exc
        raise last_exc or ConnectionError("All Cloudflare endpoints failed")

    def _schedule_refill(self, dc: int, is_test_dc: bool) -> None:
        if self._closed:
            return
        key = (dc, is_test_dc)
        if key in self._refilling:
            return
        bucket = self._idle.setdefault(key, deque())
        if len(bucket) >= self.pool_size:
            return
        self._refilling.add(key)

        async def _fill():
            try:
                while not self._closed and len(bucket) < self.pool_size:
                    sock = await self._connect_socket(dc, is_test_dc)
                    if self._closed or len(bucket) >= self.pool_size:
                        await sock.close()
                        break
                    bucket.append(sock)
            except Exception as exc:
                log.debug("Refill DC%d failed: %r", dc, exc)
            finally:
                self._refilling.discard(key)

        task = asyncio.create_task(_fill())
        self._refill_tasks.add(task)
        task.add_done_callback(self._refill_tasks.discard)

    async def flush_stream_idle(self) -> None:
        """Close and clear idle stream sockets, then pre-warm with updated settings."""
        close_tasks = []
        for bucket in list(self._stream_idle.values()):
            while bucket:
                close_tasks.append(bucket.popleft().close())
        self._stream_idle.clear()
        if close_tasks:
            await asyncio.gather(*close_tasks, return_exceptions=True)
        for dc in (2, 4, 203):
            self._schedule_stream_refill(dc, False)

    def mark_domain_failed(self, host: str) -> None:
        """Put a public CF domain on cooldown after HTTP rejection or silent upstream drop."""
        h = (host or "").strip().lower()
        if not h or "." not in h:
            return
        parts = h.split(".", 1)
        if parts[0].startswith("kws") and parts[0][3:].isdigit():
            h = parts[1]
        self._cf_domain_cooldown[h] = time.monotonic() + CF_DOMAIN_COOLDOWN_SECONDS

    def _pick_public_domain(self, tried: Set[str]) -> str:
        now = time.monotonic()
        domains = self.public_domains
        candidates = [
            d for d in domains
            if d not in tried and now >= self._cf_domain_cooldown.get(d, 0.0)
        ]
        if not candidates:
            candidates = [d for d in domains if d not in tried] or domains
        dom = candidates[self._cf_domain_cursor % len(candidates)]
        self._cf_domain_cursor += 1
        return dom

    async def _connect_cf_public_socket(
        self, dc: int, dst_ip: str, *, use_tls: bool
    ) -> StreamingWorkerSocket:
        """Connect over public Cloudflare proxy domains (Port 443 TLS or Port 80 ws://)."""
        last_exc: Optional[Exception] = None
        cf_port = 443 if use_tls else 80
        now = time.monotonic()
        fast_ips = list(dict.fromkeys(
            ep[0] for ep, _ in sorted(self._endpoint_rtt.items(), key=lambda kv: kv[1])
        ))
        all_ips = fast_ips + [ip for ip in CF_ANYCAST_IPS if ip not in fast_ips]
        healthy_ips = [ip for ip in all_ips if now >= self._endpoint_cooldown.get((ip, cf_port), 0.0)]
        candidate_ips = healthy_ips or all_ips

        tried_domains: Set[str] = set()
        attempts = min(8, max(6, len(self.public_domains)))
        for attempt in range(attempts):
            base_domain = self._pick_public_domain(tried_domains)
            cf_ip = candidate_ips[attempt % len(candidate_ips)]
            cf_host = f"kws{dc}.{base_domain}"
            t0 = time.monotonic()
            try:
                sock = await StreamingWorkerSocket.connect(
                    dc=dc,
                    dst_ip=dst_ip,
                    cf_ip=cf_ip,
                    cf_port=cf_port,
                    sni_host=cf_host,
                    http_host=cf_host,
                    path="/apiws",
                    is_cf_direct=True,
                    ssl_ctx=self.ssl_ctx,
                    frag_tls=(self.frag_tls if use_tls else False),
                    use_tls=use_tls,
                )
                self._cf_domain_cooldown.pop(base_domain, None)
                self._mark_endpoint_ok((cf_ip, cf_port), time.monotonic() - t0)
                self.stats.sockets_opened += 1
                log.info(
                    "Stream DC%d connected via CF %s %s (%s:%d)",
                    dc,
                    "Port 443" if use_tls else "Port 80",
                    cf_host,
                    cf_ip,
                    cf_port,
                )
                return sock
            except (WorkerRateLimitError, UpstreamHttpRejectError) as exc:
                self.stats.sockets_failed += 1
                tried_domains.add(base_domain)
                self._cf_domain_cooldown[base_domain] = time.monotonic() + CF_DOMAIN_COOLDOWN_SECONDS
                last_exc = exc
            except Exception as exc:
                self.stats.sockets_failed += 1
                self._mark_endpoint_failed((cf_ip, cf_port))
                last_exc = exc
        raise last_exc or ConnectionError(
            f"All public CF {'Port 443' if use_tls else 'Port 80'} endpoints failed for DC{dc}"
        )

    def _record_tls_result(self, *, tls_ok: bool, tls_timed_out: bool = False) -> None:
        if tls_ok:
            self._tls_timeout_streak = 0
        elif tls_timed_out and self.allow_port80_fallback:
            self._tls_timeout_streak += 1
            if self._tls_timeout_streak >= 2 and not self.prefer_port80_cf:
                self.prefer_port80_cf = True
                log.info("Runtime auto-fallback: switching to CF Port 80 after repeated TLS timeouts")

    async def _connect_stream_socket(
        self,
        dc: int,
        is_test_dc: bool,
        *,
        exclude: Optional[Set[Tuple[str, int]]] = None,
    ) -> StreamingWorkerSocket:
        dst_ip = self.resolve_dc_ip(dc, is_test_dc)
        last_exc: Optional[Exception] = None
        can_cf_public = (not is_test_dc) and dc in (1, 2, 3, 4, 5, 203)

        if self.prefer_port80_cf and can_cf_public and not self.has_custom_worker:
            try:
                return await self._connect_cf_public_socket(dc, dst_ip, use_tls=False)
            except Exception as exc:
                last_exc = exc

        if self.has_custom_worker:
            tried: Set[Tuple[str, int]] = set(exclude or ())
            for attempt in range(max(4, len(self.worker_domains) * 2)):
                avail_workers = self._available_worker_domains()
                if not avail_workers:
                    break
                w_dom = avail_workers[attempt % len(avail_workers)]
                ep = self._pick_endpoint(exclude=tried)
                tried.add(ep)
                try_port80_first = (
                    self.prefer_port80_cf
                    and self.allow_port80_fallback
                    and w_dom.lower() not in self._worker_no_port80
                )
                plans = (
                    ((False, 80), (True, ep[1]))
                    if try_port80_first
                    else (
                        ((True, ep[1]), (False, 80))
                        if (self.allow_port80_fallback and w_dom.lower() not in self._worker_no_port80)
                        else ((True, ep[1]),)
                    )
                )
                tls_timed_out = False
                for use_tls, cf_port in plans:
                    if not use_tls and (not tls_timed_out and not try_port80_first):
                        continue
                    t0 = time.monotonic()
                    try:
                        sock = await StreamingWorkerSocket.connect(
                            dc=dc,
                            dst_ip=dst_ip,
                            cf_ip=ep[0],
                            cf_port=cf_port,
                            sni_host=w_dom,
                            http_host=w_dom,
                            path=f"/apiws?dst={dst_ip}&dc={dc}",
                            is_cf_direct=False,
                            ssl_ctx=self.ssl_ctx,
                            frag_tls=(self.frag_tls if use_tls else False),
                            use_tls=use_tls,
                        )
                        self._mark_endpoint_ok((ep[0], cf_port), time.monotonic() - t0)
                        if use_tls:
                            self._record_tls_result(tls_ok=True)
                        elif tls_timed_out:
                            self._record_tls_result(tls_ok=False, tls_timed_out=True)
                        self.stats.sockets_opened += 1
                        return sock
                    except WorkerRateLimitError as exc:
                        self.stats.sockets_failed += 1
                        self._mark_worker_rate_limited(w_dom)
                        last_exc = exc
                        break
                    except UpstreamHttpRejectError as exc:
                        self.stats.sockets_failed += 1
                        last_exc = exc
                        if not use_tls and exc.status in (301, 302, 307, 308, 403):
                            self._worker_no_port80.add(w_dom.lower())
                        else:
                            self._mark_endpoint_failed((ep[0], cf_port))
                    except (TimeoutError, asyncio.TimeoutError) as exc:
                        self.stats.sockets_failed += 1
                        self._mark_endpoint_failed((ep[0], cf_port))
                        last_exc = exc
                        if use_tls:
                            tls_timed_out = True
                    except Exception as exc:
                        self.stats.sockets_failed += 1
                        self._mark_endpoint_failed((ep[0], cf_port))
                        last_exc = exc

        if can_cf_public:
            if self.prefer_port80_cf:
                try:
                    return await self._connect_cf_public_socket(dc, dst_ip, use_tls=False)
                except Exception as exc:
                    last_exc = exc
            tls_timed_out = False
            try:
                sock = await self._connect_cf_public_socket(dc, dst_ip, use_tls=True)
                self._record_tls_result(tls_ok=True)
                return sock
            except (TimeoutError, asyncio.TimeoutError) as exc:
                tls_timed_out = True
                last_exc = exc
            except Exception as exc:
                last_exc = exc
            if self.allow_port80_fallback:
                try:
                    sock = await self._connect_cf_public_socket(dc, dst_ip, use_tls=False)
                    if tls_timed_out:
                        self._record_tls_result(tls_ok=False, tls_timed_out=True)
                    return sock
                except Exception as exc:
                    last_exc = exc

        raise last_exc or ConnectionError(f"All streaming endpoints failed for DC{dc}")

    def _schedule_stream_refill(self, dc: int, is_test_dc: bool) -> None:
        if self._closed:
            return
        key = (dc, is_test_dc)
        if key in self._stream_refilling:
            return
        bucket = self._stream_idle.setdefault(key, deque())
        target = max(1, self.pool_size)
        if len(bucket) >= target:
            return
        self._stream_refilling.add(key)

        async def _fill():
            try:
                while not self._closed and len(bucket) < target:
                    sock = await self._connect_stream_socket(dc, is_test_dc)
                    if self._closed or len(bucket) >= target:
                        await sock.close()
                        break
                    bucket.append(sock)
            except Exception as exc:
                log.debug("Stream refill DC%d failed: %r", dc, exc)
            finally:
                self._stream_refilling.discard(key)

        task = asyncio.create_task(_fill())
        self._refill_tasks.add(task)
        task.add_done_callback(self._refill_tasks.discard)

    async def acquire_stream_socket(self, dc: int, is_test_dc: bool) -> StreamingWorkerSocket:
        key = (dc, is_test_dc)
        bucket = self._stream_idle.setdefault(key, deque())
        while bucket:
            sock = bucket.popleft()
            if sock.is_idle_healthy():
                self._schedule_stream_refill(dc, is_test_dc)
                return sock
            self.stats.sockets_rotated += 1
            asyncio.create_task(sock.close())

        self._schedule_stream_refill(dc, is_test_dc)
        return await self._connect_stream_socket(dc, is_test_dc)

    async def _acquire_socket(self, dc: int, is_test_dc: bool,
                              exclude: Optional[Set[Tuple[str, int]]] = None) -> EphemeralWorkerSocket:
        key = (dc, is_test_dc)
        bucket = self._idle.setdefault(key, deque())
        while bucket:
            sock = bucket.popleft()
            if sock.can_reuse() and (not exclude or sock.endpoint not in exclude):
                self._schedule_refill(dc, is_test_dc)
                return sock
            self.stats.sockets_rotated += 1
            asyncio.create_task(sock.close())

        self._schedule_refill(dc, is_test_dc)
        return await self._connect_socket(dc, is_test_dc, exclude=exclude)

    def _release_or_retire(self, sock: EphemeralWorkerSocket, dc: int, is_test_dc: bool) -> None:
        if not self._closed and sock.can_reuse():
            bucket = self._idle.setdefault((dc, is_test_dc), deque())
            if len(bucket) < self.pool_size:
                bucket.appendleft(sock)
                return
        self.stats.sockets_rotated += 1
        asyncio.create_task(sock.close())
        self._schedule_refill(dc, is_test_dc)

    async def _fetch_remaining_slices(
        self, dc: int, is_test_dc: bool, slice_id: str, total_len: int, initial_chunk: bytes
    ) -> bytes:
        """Fetch remaining 6KB slices across separate fresh carousel sockets."""
        parts: Dict[int, bytes] = {0: initial_chunk}
        offsets = list(range(len(initial_chunk), total_len, 6144))

        async def _fetch_one(off: int) -> None:
            sock = await self._acquire_socket(dc, is_test_dc)
            try:
                chunk = await sock.get_v2_slice(slice_id, off, 6144)
                parts[off] = chunk
                self.stats.v2_slices_fetched += 1
                self._release_or_retire(sock, dc, is_test_dc)
            except Exception:
                await sock.close()
                raise

        await asyncio.gather(*(_fetch_one(off) for off in offsets))
        return b"".join(parts[off] for off in sorted(parts))

    async def execute_mtproto_request(
        self, dc: int, mt_body: bytes, *, is_test_dc: bool = False, retries: int = 3
    ) -> bytes:
        """Execute a stateless MTProto POST /api request with automatic socket rotation."""
        excluded_eps: Set[Tuple[str, int]] = set()
        last_exc: Optional[Exception] = None

        for attempt in range(retries):
            sock = await self._acquire_socket(dc, is_test_dc, exclude=excluded_eps)
            try:
                if self.active_mode == "v2":
                    status, headers, body = await sock.post_mtproto_v2(mt_body)
                    self.stats.bytes_tx += len(mt_body)
                    if status in (403, 404, 429, 444):
                        raise UpstreamTransportError(-status, f"HTTP {status} from DC{dc}")
                    if status == 206 and "x-slice-id" in headers:
                        slice_id = headers["x-slice-id"]
                        total_len = int(headers["x-total-len"])
                        self._release_or_retire(sock, dc, is_test_dc)
                        full_body = await self._fetch_remaining_slices(
                            dc, is_test_dc, slice_id, total_len, body
                        )
                        self.stats.bytes_rx += len(full_body)
                        self.stats.requests_ok += 1
                        return full_body
                    if status != 200:
                        raise ConnectionError(f"Worker /v2/sync HTTP {status}")
                    if len(body) == 4:
                        code, = struct.unpack("<i", body)
                        if code < 0:
                            raise UpstreamTransportError(code, f"MTProto error {code} from DC{dc}")
                    self._release_or_retire(sock, dc, is_test_dc)
                    self.stats.bytes_rx += len(body)
                    self.stats.requests_ok += 1
                    return body

                # V1 WebSocket tunnel mode
                reply = await sock.post_mtproto_v1(mt_body)
                self.stats.bytes_tx += len(mt_body)
                self.stats.bytes_rx += len(reply)
                self.stats.requests_ok += 1
                self._release_or_retire(sock, dc, is_test_dc)
                return reply

            except UpstreamTransportError:
                await sock.close()
                raise
            except WorkerRateLimitError:
                await sock.close()
                self.stats.requests_failed += 1
                raise
            except Exception as exc:
                last_exc = exc
                excluded_eps.add(sock.endpoint)
                self._mark_endpoint_failed(sock.endpoint)
                asyncio.create_task(sock.close())
                if attempt + 1 < retries:
                    self.stats.requests_retried += 1
                    log.debug(
                        "DC%d request attempt %d/%d via %s:%d failed (%r), rotating",
                        dc, attempt + 1, retries, sock.cf_ip, sock.cf_port, exc,
                    )

        self.stats.requests_failed += 1
        raise last_exc or ConnectionError(f"DC{dc} request failed after {retries} retries")

    def active_idle_count(self) -> int:
        return sum(len(q) for q in self._idle.values()) + sum(len(q) for q in self._stream_idle.values())

    async def close(self) -> None:
        self._closed = True
        for task in list(self._refill_tasks):
            task.cancel()
        await asyncio.gather(*self._refill_tasks, return_exceptions=True)
        self._refill_tasks.clear()
        close_tasks = []
        for bucket in list(self._idle.values()) + list(self._stream_idle.values()):
            while bucket:
                close_tasks.append(bucket.popleft().close())
        self._idle.clear()
        self._stream_idle.clear()
        if close_tasks:
            await asyncio.gather(*close_tasks, return_exceptions=True)
