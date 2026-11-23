"""Bridges a local Telegram MTProto client session to a full-duplex WebSocket tunnel."""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from typing import Optional, Set

from .carousel import (
    DcCarouselPool,
    StreamingWorkerSocket,
    UpstreamTransportError,
    WorkerRateLimitError,
)
from .crypto import (
    ClientHandshake,
    MsgSplitter,
    encode_mtproto_reply,
    generate_relay_init,
    read_mtproto_packet,
)

log = logging.getLogger("freetg.session")

MAX_INFLIGHT = 6
MAX_REPLAY_BODY_BYTES = 16384
FAST_POLL_INTERVALS = (1.5, 2.5, 4.0)
STEADY_POLL_INTERVAL = 15.0
WS_KEEPALIVE_SECONDS = 35.0
WS_MAX_SILENT_PINGS = 3


class ClientSession:
    """Handles one Telegram client TCP connection over a dedicated WS tunnel (with carousel fallback)."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        handshake: ClientHandshake,
        carousel: DcCarouselPool,
        label: str,
    ):
        self.reader = reader
        self.writer = writer
        self.hs = handshake
        self.carousel = carousel
        self.label = label

        self._write_lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(MAX_INFLIGHT)
        self._inflight: Set[asyncio.Task] = set()
        self._closed = False

        self._last_enc_body: Optional[bytes] = None
        self._last_reply_prefix: Optional[bytes] = None
        self._seen_reply_prefixes: Set[bytes] = set()
        self._last_activity = time.monotonic()
        self._poll_step = 0
        self._wakeup = asyncio.Event()

    async def _run_streaming(self, initial_ws: StreamingWorkerSocket) -> None:
        MAX_RETRY_BUFFER = 65536
        try:
            first_chunk = await asyncio.wait_for(self.reader.read(65536), timeout=30.0)
        except (asyncio.TimeoutError, OSError, ConnectionError):
            await initial_ws.close()
            return

        if not first_chunk:
            await initial_ws.close()
            return

        first_plain = self.hs.decryptor.update(first_chunk)
        self.carousel.stats.bytes_tx += len(first_chunk)
        pending_plain = bytearray(first_plain)
        can_replay = len(pending_plain) <= MAX_RETRY_BUFFER

        ws: Optional[StreamingWorkerSocket] = initial_ws
        excluded_eps = set()
        for attempt in range(3):
            if ws is None:
                try:
                    ws = await self.carousel._connect_stream_socket(
                        self.hs.dc_id, self.hs.is_test_dc, exclude=excluded_eps
                    )
                except Exception as exc:
                    log.warning("[%s] DC%d stream reconnect failed: %r", self.label, self.hs.dc_id, exc)
                    return

            relay_init, tg_enc, tg_dec = generate_relay_init(self.hs.proto_tag, self.hs.dc_idx)
            splitter = MsgSplitter(self.hs.proto_tag) if ws.is_cf_direct else None
            boot_plain = bytes(pending_plain)
            boot_tg = tg_enc.update(boot_plain)
            last_tx_time = time.monotonic()

            try:
                if ws.is_cf_direct:
                    await ws.send_ws(relay_init)
                    parts = splitter.split(boot_tg, boot_plain) if splitter else [boot_tg]
                    if len(parts) > 1:
                        await ws.send_ws_batch(parts)
                    elif parts:
                        await ws.send_ws(parts[0])
                else:
                    # Atomic first write avoids async message-handler races in the CF Worker.
                    await ws.send_ws(relay_init + boot_tg)
                last_tx_time = time.monotonic()
            except Exception as exc:
                log.debug("[%s] DC%d initial stream write failed (attempt %d): %r", self.label, self.hs.dc_id, attempt + 1, exc)
                await ws.close()
                ws = None
                continue

            received_downstream = False
            client_eof = False

            async def tcp_to_ws() -> None:
                nonlocal client_eof, can_replay, last_tx_time
                while not self._closed:
                    chunk = await self.reader.read(65536)
                    if not chunk:
                        client_eof = True
                        if splitter is not None:
                            tail = splitter.flush()
                            if tail:
                                last_tx_time = time.monotonic()
                                await ws.send_ws(tail[0])
                                last_tx_time = time.monotonic()
                        return
                    self.carousel.stats.bytes_tx += len(chunk)
                    plain = self.hs.decryptor.update(chunk)
                    if not received_downstream and can_replay:
                        if len(pending_plain) + len(plain) <= MAX_RETRY_BUFFER:
                            pending_plain.extend(plain)
                        else:
                            can_replay = False
                            pending_plain.clear()
                    tg_data = tg_enc.update(plain)
                    last_tx_time = time.monotonic()
                    if splitter is not None:
                        parts = splitter.split(tg_data, plain)
                        if not parts:
                            continue
                        if len(parts) > 1:
                            await ws.send_ws_batch(parts)
                        else:
                            await ws.send_ws(parts[0])
                    else:
                        await ws.send_ws(tg_data)
                    last_tx_time = time.monotonic()

            async def ws_to_tcp() -> None:
                nonlocal received_downstream
                silent_pings = 0
                while not self._closed:
                    try:
                        wait_t = 3.5 if not received_downstream else WS_KEEPALIVE_SECONDS
                        data = await ws.recv_ws(timeout=wait_t)
                        silent_pings = 0
                    except asyncio.TimeoutError:
                        if not received_downstream:
                            idle_since_tx = time.monotonic() - last_tx_time
                            threshold = 3.5 if can_replay else 25.0
                            if idle_since_tx < threshold:
                                continue
                            self.carousel._mark_endpoint_failed(ws.endpoint)
                            if ws.is_cf_direct:
                                self.carousel.mark_domain_failed(ws.host)
                            raise TimeoutError("No initial response from upstream DC")
                        silent_pings += 1
                        if silent_pings > WS_MAX_SILENT_PINGS:
                            return
                        await ws.send_ping()
                        continue
                    if data is None:
                        return
                    if not received_downstream:
                        received_downstream = True
                        pending_plain.clear()
                    self.carousel.stats.bytes_rx += len(data)
                    plain = tg_dec.update(data)
                    out = self.hs.encryptor.update(plain)
                    self.writer.write(out)
                    await self.writer.drain()

            tasks = [
                asyncio.create_task(tcp_to_ws()),
                asyncio.create_task(ws_to_tcp()),
            ]
            should_retry = False
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    if not t.cancelled():
                        exc = t.exception()
                        if exc is not None and not isinstance(
                            exc, (asyncio.IncompleteReadError, ConnectionError, OSError, asyncio.CancelledError)
                        ):
                            log.debug("[%s] DC%d stream ended: %r", self.label, self.hs.dc_id, exc)
                for t in pending:
                    t.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                if (
                    not received_downstream
                    and can_replay
                    and not client_eof
                    and not self._closed
                    and attempt < 2
                ):
                    should_retry = True
                    excluded_eps.add(ws.endpoint)
                    self.carousel._mark_endpoint_failed(ws.endpoint)
                    if ws.is_cf_direct:
                        self.carousel.mark_domain_failed(ws.host)
                    log.debug("[%s] DC%d upstream closed before first byte (%s:%d), retrying fresh socket",
                              self.label, self.hs.dc_id, ws.cf_ip, ws.cf_port)
            finally:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                await ws.close()
                ws = None

            if not should_retry:
                return

    async def _send_to_client(self, reply_body: bytes) -> None:
        if self._closed or not reply_body:
            return
        framed = encode_mtproto_reply(reply_body, self.hs.proto_tag)
        async with self._write_lock:
            if self._closed:
                return
            self.writer.write(self.hs.encryptor.update(framed))
            await self.writer.drain()

    async def _dispatch_packet(self, body: bytes, *, is_poll: bool = False) -> None:
        async with self._sem:
            if self._closed:
                return
            try:
                reply = await self.carousel.execute_mtproto_request(
                    self.hs.dc_id,
                    body,
                    is_test_dc=self.hs.is_test_dc,
                )
            except UpstreamTransportError as exc:
                log.warning("[%s] DC%d upstream transport error %d", self.label, self.hs.dc_id, exc.code)
                try:
                    await self._send_to_client(struct.pack("<i", exc.code))
                except Exception:
                    pass
                self.close_now()
                return
            except WorkerRateLimitError as exc:
                log.error("[%s] %s", self.label, exc)
                self.close_now()
                return
            except Exception as exc:
                log.warning("[%s] DC%d carousel error: %r", self.label, self.hs.dc_id, exc)
                self.close_now()
                return

            if not reply or self._closed:
                return

            prefix = reply[:24]
            if is_poll:
                if prefix in self._seen_reply_prefixes or prefix == self._last_reply_prefix:
                    return
                self._poll_step = 0
                self._last_activity = time.monotonic()

            self._last_reply_prefix = prefix
            if len(self._seen_reply_prefixes) > 128:
                self._seen_reply_prefixes.clear()
            self._seen_reply_prefixes.add(prefix)

            try:
                await self._send_to_client(reply)
            except (OSError, ConnectionError):
                self.close_now()

    def _spawn_request(self, body: bytes, *, is_poll: bool = False) -> None:
        if self._closed:
            return
        task = asyncio.create_task(self._dispatch_packet(body, is_poll=is_poll))
        self._inflight.add(task)
        task.add_done_callback(self._on_task_done)

    def _on_task_done(self, task: asyncio.Task) -> None:
        self._inflight.discard(task)
        if not self._inflight:
            self._wakeup.set()

    async def _upload_loop(self) -> None:
        while not self._closed:
            body, _quick = await read_mtproto_packet(
                self.reader, self.hs.decryptor, self.hs.proto_tag
            )
            self._last_activity = time.monotonic()
            self._poll_step = 0

            if (
                not self.hs.is_media
                and body[:8] != b"\x00" * 8
                and len(body) <= MAX_REPLAY_BODY_BYTES
            ):
                if body != self._last_enc_body:
                    self._last_enc_body = body
                    self._last_reply_prefix = None

            self._spawn_request(body, is_poll=False)

    async def _idle_poll_loop(self) -> None:
        if self.hs.is_media:
            while not self._closed:
                await asyncio.sleep(5.0)
            return

        while not self._closed:
            if self._poll_step < len(FAST_POLL_INTERVALS):
                wait_s = FAST_POLL_INTERVALS[self._poll_step]
            else:
                wait_s = STEADY_POLL_INTERVAL

            self._wakeup.clear()
            try:
                await asyncio.wait_for(self._wakeup.wait(), timeout=wait_s)
                continue
            except asyncio.TimeoutError:
                pass

            if self._closed:
                return
            if self._inflight or self._last_enc_body is None:
                continue
            if time.monotonic() - self._last_activity < wait_s * 0.9:
                continue

            self._poll_step += 1
            self._last_activity = time.monotonic()
            self._spawn_request(self._last_enc_body, is_poll=True)

    async def _run_stateless_carousel(self) -> None:
        upload_task = asyncio.create_task(self._upload_loop())
        poll_task = asyncio.create_task(self._idle_poll_loop())
        try:
            done, pending = await asyncio.wait(
                (upload_task, poll_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for t in done:
                exc = t.exception()
                if exc is not None and not isinstance(
                    exc, (asyncio.IncompleteReadError, ConnectionError, OSError, asyncio.CancelledError)
                ):
                    log.debug("[%s] Stateless session ended with error: %r", self.label, exc)
        finally:
            for t in list(self._inflight):
                t.cancel()
            if self._inflight:
                await asyncio.gather(*self._inflight, return_exceptions=True)

    def close_now(self) -> None:
        if not self._closed:
            self._closed = True
            self._wakeup.set()
            try:
                self.writer.close()
            except Exception:
                pass

    async def run(self) -> None:
        try:
            ws = None
            try:
                ws = await self.carousel.acquire_stream_socket(
                    self.hs.dc_id, self.hs.is_test_dc
                )
            except Exception as exc:
                log.warning(
                    "[%s] DC%d stream connect failed (%r), falling back to stateless carousel",
                    self.label,
                    self.hs.dc_id,
                    exc,
                )

            if ws is not None:
                await self._run_streaming(ws)
            elif self.carousel.has_custom_worker:
                await self._run_stateless_carousel()
            else:
                log.debug("[%s] DC%d stream unavailable and no custom Worker for stateless fallback", self.label, self.hs.dc_id)
        finally:
            self.close_now()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
