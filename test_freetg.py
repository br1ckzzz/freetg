"""Unit and live end-to-end integration tests for FreeTG."""

from __future__ import annotations

import asyncio
import hashlib
import os
import struct
import time
import unittest

from freetg import __version__
from freetg.app_config import parse_worker_domains, sanitize_worker_domain, to_freetg_config
from freetg.carousel import DcCarouselPool
from freetg.crypto import (
    AesCtr,
    PROTO_TAG_ABRIDGED,
    PROTO_TAG_INTERMEDIATE,
    PROTO_TAG_SECURE,
    encode_mtproto_reply,
    normalize_secret,
    read_mtproto_packet,
    try_handshake,
)
from freetg.server import DEFAULT_SECRET, DEFAULT_WORKER_DOMAIN, FreeTGConfig, FreeTGProxyServer


def _build_client_obfs2(secret: bytes, dc_idx: int, proto_tag: bytes):
    """Build client->proxy 64-byte obfuscated2 handshake + client enc/dec ciphers."""
    while True:
        rnd = bytearray(os.urandom(64))
        if rnd[0] == 0xEF:
            continue
        if bytes(rnd[:4]) in (b"HEAD", b"POST", b"GET ", b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd", b"\x16\x03\x01\x02"):
            continue
        if rnd[4:8] == b"\x00\x00\x00\x00":
            continue
        break

    rnd_bytes = bytes(rnd)
    enc_prekey_iv = rnd_bytes[8:56]
    enc_key = hashlib.sha256(enc_prekey_iv[:32] + secret).digest()
    enc_iv = enc_prekey_iv[32:]
    clt_enc = AesCtr(enc_key, enc_iv)

    dec_prekey_iv = enc_prekey_iv[::-1]
    dec_key = hashlib.sha256(dec_prekey_iv[:32] + secret).digest()
    dec_iv = dec_prekey_iv[32:]
    clt_dec = AesCtr(dec_key, dec_iv)

    ks = clt_enc.update(b"\x00" * 64)
    tail_plain = proto_tag + struct.pack("<h", dc_idx) + os.urandom(2)
    handshake = bytearray(rnd_bytes)
    for i in range(8):
        handshake[56 + i] = tail_plain[i] ^ ks[56 + i]

    return bytes(handshake), clt_enc, clt_dec


def _frame_client_packet(body: bytes, proto_tag: bytes) -> bytes:
    if proto_tag == PROTO_TAG_ABRIDGED:
        words = len(body) // 4
        prefix = bytes([words]) if words < 0x7F else b"\x7f" + words.to_bytes(3, "little")
        return prefix + body
    if proto_tag == PROTO_TAG_SECURE:
        pad = os.urandom(4)
        return struct.pack("<I", len(body) + len(pad)) + body + pad
    return struct.pack("<I", len(body)) + body


def _make_req_pq_multi(seq: int = 0) -> bytes:
    nonce = os.urandom(16)
    msg_id = (int(time.time() * (2**32)) & ~3) + seq * 4
    return struct.pack("<QQII", 0, msg_id, 20, 0xBE7E8EF1) + nonce


class CryptoUnitTests(unittest.TestCase):
    def test_normalize_secret(self):
        s1 = normalize_secret(DEFAULT_SECRET)
        s2 = normalize_secret("dd" + DEFAULT_SECRET)
        self.assertEqual(s1, s2)
        self.assertEqual(len(s1), 16)

    def test_handshake_all_tags_and_media(self):
        secret = normalize_secret(DEFAULT_SECRET)
        for tag in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
            for dc_idx, exp_dc, exp_media in ((2, 2, False), (-4, 4, True), (10002, 2, False)):
                hs_bytes, _, _ = _build_client_obfs2(secret, dc_idx, tag)
                parsed = try_handshake(hs_bytes, secret)
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed.dc_id, exp_dc)
                self.assertEqual(parsed.is_media, exp_media)
                self.assertEqual(parsed.is_test_dc, dc_idx >= 10000)
                self.assertEqual(parsed.proto_tag, tag)

    def test_public_pool_defaults_and_domain_parsing(self):
        self.assertEqual(__version__, "0.2.1")
        self.assertEqual(DEFAULT_WORKER_DOMAIN, "")
        self.assertEqual(parse_worker_domains(""), [])
        self.assertEqual(
            parse_worker_domains(" https://one.workers.dev/apiws , two.workers.dev; ONE.workers.dev invalid "),
            ["one.workers.dev", "two.workers.dev"],
        )
        self.assertEqual(sanitize_worker_domain("https://my.workers.dev/"), "my.workers.dev")
        self.assertEqual(sanitize_worker_domain(""), "")

        cfg = to_freetg_config({
            "host": "127.0.0.1",
            "port": 1080,
            "secret": DEFAULT_SECRET,
            "worker_domain": "",
        })
        self.assertEqual(cfg.worker_domain, "")
        self.assertFalse(cfg.prefer_port80_cf)
        pool = DcCarouselPool(cfg.worker_domain, mode="auto", pool_size=1)
        self.assertFalse(pool.has_custom_worker)
        self.assertEqual(len(pool.public_domains), 20)
        self.assertTrue(all(d.endswith(".co.uk") for d in pool.public_domains))

        cfg_p80 = to_freetg_config({"bypass_mode": "port80"})
        self.assertTrue(cfg_p80.prefer_port80_cf)
        self.assertFalse(cfg_p80.frag_tls)

        cfg_frag = to_freetg_config({"bypass_mode": "tls_frag"})
        self.assertFalse(cfg_frag.prefer_port80_cf)
        self.assertTrue(cfg_frag.frag_tls)

    def test_domain_vs_endpoint_cooldown(self):
        pool = DcCarouselPool("", mode="v1", pool_size=1)
        pool.mark_domain_failed("kws203.lovetrue.co.uk")
        self.assertIn("lovetrue.co.uk", pool._cf_domain_cooldown)
        picked = pool._pick_public_domain(set())
        self.assertNotEqual(picked, "lovetrue.co.uk")

    def test_packet_roundtrip(self):
        async def _run():
            secret = normalize_secret(DEFAULT_SECRET)
            for tag in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
                hs_bytes, clt_enc, clt_dec = _build_client_obfs2(secret, 2, tag)
                parsed = try_handshake(hs_bytes, secret)
                self.assertIsNotNone(parsed)
                payload = _make_req_pq_multi(1)
                wire = clt_enc.update(_frame_client_packet(payload, tag))

                sr = asyncio.StreamReader()
                sr.feed_data(wire)
                sr.feed_eof()
                got_body, _ = await read_mtproto_packet(sr, parsed.decryptor, tag)
                self.assertEqual(got_body, payload)

                reply_wire = parsed.encryptor.update(encode_mtproto_reply(payload, tag))
                sr2 = asyncio.StreamReader()
                sr2.feed_data(reply_wire)
                sr2.feed_eof()
                got_reply, _ = await read_mtproto_packet(sr2, clt_dec, tag)
                self.assertEqual(got_reply, payload)

        asyncio.run(_run())


class LiveCarouselIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.cfg = FreeTGConfig(
            host="127.0.0.1",
            ports=[11443],
            secret_hex=DEFAULT_SECRET,
            worker_domain=DEFAULT_WORKER_DOMAIN,
            mode="v1",
            pool_size=3,
            frag_tls=False,
            stats_interval=0,
        )
        self.server = FreeTGProxyServer(self.cfg)
        await self.server.start()
        self.secret = normalize_secret(DEFAULT_SECRET)

    async def asyncTearDown(self):
        await self.server.stop()

    async def _connect_dc_and_ping(self, dc: int, count: int, tag: bytes = PROTO_TAG_SECURE) -> int:
        reader, writer = await asyncio.open_connection("127.0.0.1", 11443)
        try:
            hs_bytes, clt_enc, clt_dec = _build_client_obfs2(self.secret, dc, tag)
            writer.write(hs_bytes)
            await writer.drain()

            ok = 0
            for i in range(count):
                req = _make_req_pq_multi(i)
                framed = _frame_client_packet(req, tag)
                writer.write(clt_enc.update(framed))
                await writer.drain()

                reply, _ = await asyncio.wait_for(
                    read_mtproto_packet(reader, clt_dec, tag), timeout=15.0
                )
                # resPQ constructor is 0x05162463 (little-endian: 63 24 16 05)
                if len(reply) >= 40 and b"\x63\x24\x16\x05" in reply:
                    ok += 1
            return ok
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_all_dcs_and_media_reachable(self):
        for dc in (1, 2, -2, 3, 4, -4, 5, 203):
            ok = await self._connect_dc_and_ping(dc, 1, PROTO_TAG_SECURE)
            self.assertEqual(ok, 1, f"DC{dc} failed to return resPQ")

    async def test_30_consecutive_packets_single_persistent_connection(self):
        ok = await self._connect_dc_and_ping(2, 30, PROTO_TAG_SECURE)
        self.assertEqual(ok, 30)
        print(
            f"\n[Integration] 30/30 MTProto resPQ over 1 persistent connection! "
            f"Upstream sockets opened={self.server.carousel.stats.sockets_opened}, "
            f"up={self.server.carousel.stats.bytes_tx}B, down={self.server.carousel.stats.bytes_rx}B"
        )


class FragmentedTlsLiveTest(unittest.IsolatedAsyncioTestCase):
    async def test_frag_tls_handshake_and_request(self):
        cfg = FreeTGConfig(
            host="127.0.0.1",
            ports=[11444],
            secret_hex=DEFAULT_SECRET,
            worker_domain=DEFAULT_WORKER_DOMAIN,
            mode="v1",
            pool_size=1,
            frag_tls=True,
            stats_interval=0,
        )
        server = FreeTGProxyServer(cfg)
        await server.start()
        try:
            secret = normalize_secret(DEFAULT_SECRET)
            reader, writer = await asyncio.open_connection("127.0.0.1", 11444)
            try:
                hs_bytes, clt_enc, clt_dec = _build_client_obfs2(secret, 4, PROTO_TAG_INTERMEDIATE)
                writer.write(hs_bytes)
                writer.write(clt_enc.update(_frame_client_packet(_make_req_pq_multi(0), PROTO_TAG_INTERMEDIATE)))
                await writer.drain()
                reply, _ = await asyncio.wait_for(
                    read_mtproto_packet(reader, clt_dec, PROTO_TAG_INTERMEDIATE), timeout=15.0
                )
                self.assertIn(b"\x63\x24\x16\x05", reply)
            finally:
                writer.close()
        finally:
            await server.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
