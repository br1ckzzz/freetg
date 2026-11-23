"""Local MTProto proxy server bridging Telegram Desktop to the FreeTG carousel."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
import logging
import socket as _socket
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Set

from .carousel import DEFAULT_POOL_SIZE_PER_DC, DcCarouselPool
from .crypto import (
    AES_BACKEND_NAME,
    HANDSHAKE_LEN,
    normalize_secret,
    try_handshake,
)

log = logging.getLogger("freetg.server")

DEFAULT_SECRET = "f1e2d3c4b5a69788796a5b4c3d2e1f00"
DEFAULT_WORKER_DOMAIN = ""


def _human_bytes(n: int) -> str:
    val = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(val) < 1024.0:
            return f"{val:.1f}{unit}"
        val /= 1024.0
    return f"{val:.1f}TB"


def install_proactor_socket_guard(loop: asyncio.AbstractEventLoop) -> None:
    """Prevent stale unclosed sockets when WinError aborts shutdown() in ProactorEventLoop."""
    if sys.platform != "win32" or not isinstance(loop, asyncio.ProactorEventLoop):
        return
    try:
        from asyncio.proactor_events import _ProactorSocketTransport
    except Exception:
        return

    orig = getattr(_ProactorSocketTransport, "_call_connection_lost", None)
    if orig is None or getattr(orig, "_freetg_guarded", False):
        return

    def _safe_call_connection_lost(self, exc):
        if self._called_connection_lost:
            return
        try:
            self._protocol.connection_lost(exc)
        finally:
            sock = self._sock
            if sock is not None:
                try:
                    if hasattr(sock, "shutdown") and sock.fileno() != -1:
                        sock.shutdown(_socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
                self._sock = None
            server = self._server
            if server is not None:
                try:
                    if sys.version_info >= (3, 13):
                        server._detach(self)
                    else:
                        server._detach()
                except Exception:
                    pass
                self._server = None
            self._called_connection_lost = True

    _safe_call_connection_lost._freetg_guarded = True
    _ProactorSocketTransport._call_connection_lost = _safe_call_connection_lost


class _TrackedClientProtocol(asyncio.StreamReaderProtocol):
    """StreamReaderProtocol that notifies pending upstream dials when local client disconnects."""

    def __init__(
        self,
        stream_reader: asyncio.StreamReader,
        client_connected_cb: Callable[[asyncio.StreamReader, asyncio.StreamWriter], None],
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        super().__init__(stream_reader, client_connected_cb, loop=loop)
        self._dial_cancel_cb: Optional[Callable[[], None]] = None

    def _fire_dial_cancel(self) -> None:
        cb = self._dial_cancel_cb
        self._dial_cancel_cb = None
        if cb is not None:
            cb()

    def eof_received(self):
        keep_open = super().eof_received()
        self._fire_dial_cancel()
        return keep_open

    def connection_lost(self, exc):
        super().connection_lost(exc)
        self._fire_dial_cancel()


@contextmanager
def cancel_on_client_gone(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Cancel the running task immediately if the local Telegram client closes while dialing upstream."""
    if reader.at_eof() or writer.is_closing():
        raise asyncio.CancelledError()
    transport = writer.transport
    protocol = transport.get_protocol() if transport is not None else None
    if not isinstance(protocol, _TrackedClientProtocol):
        yield
        return
    task = asyncio.current_task()
    if task is None:
        yield
        return

    def _cancel() -> None:
        if not task.done():
            task.cancel()

    protocol._dial_cancel_cb = _cancel
    try:
        yield
    finally:
        if protocol._dial_cancel_cb is _cancel:
            protocol._dial_cancel_cb = None


from .session import ClientSession


@dataclass
class FreeTGConfig:
    host: str = "127.0.0.1"
    ports: List[int] = field(default_factory=lambda: [1080])
    secret_hex: str = DEFAULT_SECRET
    worker_domain: str = DEFAULT_WORKER_DOMAIN
    mode: str = "auto"
    pool_size: int = DEFAULT_POOL_SIZE_PER_DC
    frag_tls: bool = False
    prefer_port80_cf: bool = False
    allow_port80_fallback: bool = True
    auto_tls_frag: bool = True
    stats_interval: float = 30.0
    verbose: bool = False


class FreeTGProxyServer:
    """Asyncio server accepting MTProto dd-secret clients and routing via DcCarouselPool."""

    def __init__(self, config: FreeTGConfig):
        self.config = config
        self.secret_bytes = normalize_secret(config.secret_hex)
        self.secret_hex_clean = self.secret_bytes.hex()
        self.carousel = DcCarouselPool(
            config.worker_domain,
            mode=config.mode,
            pool_size=config.pool_size,
            frag_tls=config.frag_tls,
            prefer_port80_cf=config.prefer_port80_cf,
            allow_port80_fallback=config.allow_port80_fallback,
            auto_tls_frag=config.auto_tls_frag,
        )
        self._servers: List[asyncio.AbstractServer] = []
        self._client_tasks: Set[asyncio.Task] = set()
        self._stats_task: Optional[asyncio.Task] = None
        self._connections_total = 0
        self._connections_active = 0
        self._connections_bad = 0
        self._stopping = False

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._connections_total += 1
        self._connections_active += 1
        peer = writer.get_extra_info("peername")
        label = f"{peer[0]}:{peer[1]}" if peer else "?"

        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            except (OSError, AttributeError):
                pass
            for opt in (_socket.SO_RCVBUF, _socket.SO_SNDBUF):
                try:
                    sock.setsockopt(_socket.SOL_SOCKET, opt, 262144)
                except (OSError, AttributeError):
                    pass

        try:
            handshake = await asyncio.wait_for(
                reader.readexactly(HANDSHAKE_LEN), timeout=10.0
            )
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            self._connections_active -= 1
            writer.close()
            return

        hs = try_handshake(handshake, self.secret_bytes)
        if hs is None:
            self._connections_bad += 1
            log.warning("[%s] Bad MTProto handshake (wrong secret or non-obfs2 client)", label)
            self._connections_active -= 1
            writer.close()
            return

        log.info(
            "[%s] Client connected -> DC%d%s%s",
            label,
            hs.dc_id,
            "t" if hs.is_test_dc else "",
            " (media)" if hs.is_media else "",
        )
        session = ClientSession(reader, writer, hs, self.carousel, label)
        try:
            await session.run()
        finally:
            self._connections_active -= 1
            log.debug("[%s] Client disconnected (DC%d)", label, hs.dc_id)

    def _on_client_connected(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._stopping:
            writer.close()
            return
        task = asyncio.create_task(self._handle_client(reader, writer))
        self._client_tasks.add(task)
        task.add_done_callback(self._client_tasks.discard)

    async def _stats_loop(self) -> None:
        while not self._stopping:
            await asyncio.sleep(self.config.stats_interval)
            if self._stopping:
                return
            st = self.carousel.stats
            log.info(
                "stats: active=%d total=%d bad=%d | reqs_ok=%d retried=%d failed=%d | "
                "sockets_open=%d rotated=%d idle=%d | up=%s down=%s%s",
                self._connections_active,
                self._connections_total,
                self._connections_bad,
                st.requests_ok,
                st.requests_retried,
                st.requests_failed,
                st.sockets_opened,
                st.sockets_rotated,
                self.carousel.active_idle_count(),
                _human_bytes(st.bytes_tx),
                _human_bytes(st.bytes_rx),
                f" | v2_slices={st.v2_slices_fetched}" if st.v2_slices_fetched else "",
            )

    def _print_banner(self) -> None:
        log.info("=" * 64)
        log.info("  FreeTG - Ephemeral Carousel MTProto Proxy")
        log.info("  AES backend   : %s", AES_BACKEND_NAME)
        worker_label = self.config.worker_domain or "public CF pool (20+ domains)"
        log.info("  Worker domain : %s (mode=%s)", worker_label, self.carousel.active_mode.upper())
        log.info(
            "  Bypass        : %s",
            "CF Port 80 (ws)" if self.config.prefer_port80_cf else ("TLS Frag" if self.config.frag_tls else "direct/auto"),
        )
        log.info("  Pool per DC   : %d pre-warmed sockets", self.config.pool_size)
        for port in self.config.ports:
            link = (
                f"tg://proxy?server={self.config.host}&port={port}"
                f"&secret=dd{self.secret_hex_clean}"
            )
            log.info("  Listen        : %s:%d", self.config.host, port)
            log.info("  Connect link  : %s", link)
        log.info("=" * 64)

    async def _start_server_with_retry(self, port: int) -> asyncio.AbstractServer:
        loop = asyncio.get_running_loop()

        def _protocol_factory():
            reader = asyncio.StreamReader(limit=65536, loop=loop)
            return _TrackedClientProtocol(reader, self._on_client_connected, loop=loop)

        last_exc: Optional[OSError] = None
        for attempt in range(5):
            try:
                return await loop.create_server(_protocol_factory, self.config.host, port)
            except OSError as exc:
                last_exc = exc
                errno = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
                if errno not in (10048, 98, 48) or attempt == 4:
                    raise
                await asyncio.sleep(0.3)
        assert last_exc is not None
        raise last_exc

    async def start(self) -> None:
        install_proactor_socket_guard(asyncio.get_running_loop())
        await self.carousel.initialize()
        try:
            for port in self.config.ports:
                srv = await self._start_server_with_retry(port)
                for s in srv.sockets:
                    try:
                        s.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
                    except (OSError, AttributeError):
                        pass
                self._servers.append(srv)
        except BaseException:
            await self.stop()
            raise

        self._print_banner()
        if self.config.stats_interval > 0:
            self._stats_task = asyncio.create_task(self._stats_loop())

    async def serve_forever(self, stop_event: Optional[asyncio.Event] = None) -> None:
        await self.start()
        try:
            if stop_event is not None:
                await stop_event.wait()
            else:
                await asyncio.gather(*(s.serve_forever() for s in self._servers))
        finally:
            await self.stop()

    async def stop(self) -> None:
        if self._stopping:
            return
        self._stopping = True
        if self._stats_task is not None:
            self._stats_task.cancel()
            await asyncio.gather(self._stats_task, return_exceptions=True)
        for srv in self._servers:
            try:
                srv.close()
            except Exception:
                pass
        # Cancel active client tasks BEFORE wait_closed(), because Python 3.12+/3.14
        # wait_closed() waits until accepted client handlers finish.
        tasks = list(self._client_tasks)
        for t in tasks:
            t.cancel()
        if tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True), timeout=1.5
                )
            except asyncio.TimeoutError:
                pass
        for srv in self._servers:
            try:
                await asyncio.wait_for(srv.wait_closed(), timeout=1.0)
            except Exception:
                pass
        try:
            await asyncio.wait_for(self.carousel.close(), timeout=1.5)
        except Exception:
            pass
