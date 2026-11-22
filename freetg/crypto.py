"""AES-256-CTR engine and MTProto obfuscated2 / transport packet framing."""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os
import struct
import sys
from dataclasses import dataclass
from typing import Optional, Tuple

ZERO_64 = b"\x00" * 64
HANDSHAKE_LEN = 64
SKIP_LEN = 8
PREKEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60

PROTO_TAG_ABRIDGED = b"\xef\xef\xef\xef"
PROTO_TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
PROTO_TAG_SECURE = b"\xdd\xdd\xdd\xdd"
SUPPORTED_PROTO_TAGS = (
    PROTO_TAG_ABRIDGED,
    PROTO_TAG_INTERMEDIATE,
    PROTO_TAG_SECURE,
)

MAX_PACKET = 4 * 1024 * 1024
MAX_PLAIN_PADDING = 256


def _init_aes_backend():
    """Select the fastest available AES-256-CTR backend with zero external deps."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        class _CryptographyAesCtr:
            __slots__ = ("_enc",)

            def __init__(self, key: bytes, iv: bytes):
                self._enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

            def update(self, data: bytes) -> bytes:
                return self._enc.update(data) if data else b""

        return _CryptographyAesCtr, "cryptography"
    except ImportError:
        pass

    # OpenSSL libcrypto bundled with Python on Windows, PyInstaller _MEIPASS, or installed on POSIX
    dll_candidates = []
    if sys.platform == "win32":
        meipass = getattr(sys, "_MEIPASS", None)
        exe_dir = os.path.dirname(os.path.abspath(sys.executable)) if sys.executable else None
        for dll_name in ("libcrypto-3.dll", "libcrypto-3-x64.dll", "libcrypto-1_1-x64.dll"):
            if meipass:
                dll_candidates.append(os.path.join(meipass, dll_name))
            if exe_dir:
                dll_candidates.append(os.path.join(exe_dir, dll_name))
            dll_candidates.append(os.path.join(sys.base_prefix, "DLLs", dll_name))
            dll_candidates.append(dll_name)
    found = ctypes.util.find_library("crypto")
    if found:
        dll_candidates.append(found)
    dll_candidates.extend(("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"))

    libcrypto = None
    for candidate in dll_candidates:
        try:
            libcrypto = ctypes.CDLL(candidate)
            break
        except OSError:
            continue

    if libcrypto is not None:
        libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
        libcrypto.EVP_aes_128_ctr.restype = ctypes.c_void_p
        libcrypto.EVP_aes_192_ctr.restype = ctypes.c_void_p
        libcrypto.EVP_aes_256_ctr.restype = ctypes.c_void_p
        libcrypto.EVP_EncryptInit_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        libcrypto.EVP_EncryptInit_ex.restype = ctypes.c_int
        libcrypto.EVP_EncryptUpdate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        libcrypto.EVP_EncryptUpdate.restype = ctypes.c_int

        evp_by_len = {
            16: libcrypto.EVP_aes_128_ctr,
            24: libcrypto.EVP_aes_192_ctr,
            32: libcrypto.EVP_aes_256_ctr,
        }

        class _LibcryptoAesCtr:
            __slots__ = ("_ctx",)

            def __init__(self, key: bytes, iv: bytes):
                if len(key) not in evp_by_len:
                    raise ValueError(f"Unsupported AES key length: {len(key)}")
                if len(iv) != 16:
                    raise ValueError(f"Unsupported CTR IV length: {len(iv)}")
                ctx = libcrypto.EVP_CIPHER_CTX_new()
                if not ctx:
                    raise RuntimeError("EVP_CIPHER_CTX_new failed")
                self._ctx = ctx
                if libcrypto.EVP_EncryptInit_ex(ctx, evp_by_len[len(key)](), None, key, iv) != 1:
                    libcrypto.EVP_CIPHER_CTX_free(ctx)
                    self._ctx = None
                    raise RuntimeError("EVP_EncryptInit_ex failed")

            def update(self, data: bytes) -> bytes:
                if not data:
                    return b""
                outlen = ctypes.c_int(0)
                buf = ctypes.create_string_buffer(len(data) + 16)
                if libcrypto.EVP_EncryptUpdate(self._ctx, buf, ctypes.byref(outlen), bytes(data), len(data)) != 1:
                    raise RuntimeError("EVP_EncryptUpdate failed")
                return buf.raw[: outlen.value]

            def __del__(self):
                ctx = getattr(self, "_ctx", None)
                if ctx:
                    libcrypto.EVP_CIPHER_CTX_free(ctx)
                    self._ctx = None

        return _LibcryptoAesCtr, "openssl-libcrypto"

    if sys.platform == "win32":
        bcrypt = ctypes.windll.bcrypt
        bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong
        ]
        bcrypt.BCryptSetProperty.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong
        ]
        bcrypt.BCryptGetProperty.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong
        ]
        bcrypt.BCryptImportKey.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong
        ]
        bcrypt.BCryptEncrypt.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong
        ]
        bcrypt.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
        bcrypt.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, ctypes.c_ulong]

        class _BcryptAesCtr:
            __slots__ = ("_alg", "_kh", "_obj", "_counter", "_ks_buf")

            def __init__(self, key: bytes, iv: bytes):
                self._counter = bytearray(iv)
                self._alg = ctypes.c_void_p()
                self._kh = ctypes.c_void_p()
                self._ks_buf = bytearray()
                bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(self._alg), "AES", None, 0)
                mode = "ChainingModeECB"
                bcrypt.BCryptSetProperty(
                    self._alg, "ChainingMode", mode, (len(mode) + 1) * 2, 0
                )
                obj_len = ctypes.c_ulong()
                res_len = ctypes.c_ulong()
                bcrypt.BCryptGetProperty(
                    self._alg, "ObjectLength", ctypes.byref(obj_len), 4, ctypes.byref(res_len), 0
                )
                self._obj = (ctypes.c_ubyte * obj_len.value)()
                blob = struct.pack("<III", 0x4D42444B, 1, len(key)) + key
                bcrypt.BCryptImportKey(
                    self._alg, None, "KeyDataBlob", ctypes.byref(self._kh),
                    self._obj, obj_len.value, blob, len(blob), 0
                )

            def update(self, data: bytes) -> bytes:
                n = len(data)
                if not n:
                    return b""
                while len(self._ks_buf) < n:
                    blocks = bytearray(1024)
                    for b in range(64):
                        blocks[b * 16 : (b + 1) * 16] = self._counter
                        for k in range(15, -1, -1):
                            self._counter[k] = (self._counter[k] + 1) & 0xFF
                            if self._counter[k] != 0:
                                break
                    in_buf = (ctypes.c_ubyte * 1024).from_buffer(blocks)
                    out_buf = (ctypes.c_ubyte * 1024)()
                    out_len = ctypes.c_ulong()
                    bcrypt.BCryptEncrypt(
                        self._kh, in_buf, 1024, None, None, 0, out_buf, 1024, ctypes.byref(out_len), 0
                    )
                    self._ks_buf.extend(bytes(out_buf))
                ks = bytes(self._ks_buf[:n])
                del self._ks_buf[:n]
                return (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")).to_bytes(n, "big")

            def __del__(self):
                if getattr(self, "_kh", None):
                    bcrypt.BCryptDestroyKey(self._kh)
                    self._kh = None
                if getattr(self, "_alg", None):
                    bcrypt.BCryptCloseAlgorithmProvider(self._alg, 0)
                    self._alg = None

        return _BcryptAesCtr, "windows-bcrypt"

    raise RuntimeError("No AES-256-CTR backend available (install cryptography or OpenSSL)")


AesCtr, AES_BACKEND_NAME = _init_aes_backend()


@dataclass(frozen=True)
class ClientHandshake:
    dc_id: int
    dc_idx: int
    is_media: bool
    is_test_dc: bool
    proto_tag: bytes
    decryptor: object
    encryptor: object


def normalize_secret(secret_hex: str) -> bytes:
    """Parse a 32-char hex secret or a 34-char 'dd...' MTProto secret."""
    cleaned = secret_hex.strip().lower()
    if len(cleaned) == 34 and cleaned.startswith("dd"):
        cleaned = cleaned[2:]
    if len(cleaned) != 32:
        raise ValueError("MTProto secret must be 32 hex chars (or 34 starting with 'dd')")
    return bytes.fromhex(cleaned)


def try_handshake(handshake: bytes, secret: bytes) -> Optional[ClientHandshake]:
    """Verify and decrypt the 64-byte obfuscated2 client handshake."""
    if len(handshake) != HANDSHAKE_LEN:
        return None

    dec_prekey_iv = handshake[SKIP_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN]
    dec_key = hashlib.sha256(dec_prekey_iv[:PREKEY_LEN] + secret).digest()
    dec_iv = dec_prekey_iv[PREKEY_LEN:]

    probe_dec = AesCtr(dec_key, dec_iv)
    decrypted = probe_dec.update(handshake)

    proto_tag = decrypted[PROTO_TAG_POS : PROTO_TAG_POS + 4]
    if proto_tag not in SUPPORTED_PROTO_TAGS:
        return None

    dc_idx = int.from_bytes(decrypted[DC_IDX_POS : DC_IDX_POS + 2], "little", signed=True)
    if dc_idx == 0:
        return None

    is_media = dc_idx < 0
    dc_raw = abs(dc_idx)
    is_test_dc = dc_raw >= 10000
    dc_id = dc_raw - 10000 if is_test_dc else dc_raw

    # Build stateful decryptor/encryptor pair for this local client connection.
    clt_dec = AesCtr(dec_key, dec_iv)
    clt_dec.update(ZERO_64)

    enc_prekey_iv = dec_prekey_iv[::-1]
    enc_key = hashlib.sha256(enc_prekey_iv[:PREKEY_LEN] + secret).digest()
    enc_iv = enc_prekey_iv[PREKEY_LEN:]
    clt_enc = AesCtr(enc_key, enc_iv)

    return ClientHandshake(
        dc_id=dc_id,
        dc_idx=-dc_id if is_media else dc_id,
        is_media=is_media,
        is_test_dc=is_test_dc,
        proto_tag=proto_tag,
        decryptor=clt_dec,
        encryptor=clt_enc,
    )


_RESERVED_FIRST_BYTES = {0xEF}
_RESERVED_STARTS = {
    b"HEAD",
    b"POST",
    b"GET ",
    b"\xee\xee\xee\xee",
    b"\xdd\xdd\xdd\xdd",
    b"\x16\x03\x01\x02",
    b"OPTI",
}
_RESERVED_CONTINUE = b"\x00\x00\x00\x00"


def generate_relay_init(proto_tag: bytes, dc_idx: int) -> Tuple[bytes, object, object]:
    """Generate a 64-byte obfuscated2 handshake for an upstream Telegram DC."""
    while True:
        rnd = bytearray(os.urandom(HANDSHAKE_LEN))
        if rnd[0] in _RESERVED_FIRST_BYTES:
            continue
        if bytes(rnd[:4]) in _RESERVED_STARTS:
            continue
        if rnd[4:8] == _RESERVED_CONTINUE:
            continue
        break

    rnd_bytes = bytes(rnd)
    enc_prekey_iv = rnd_bytes[SKIP_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN]
    tg_enc = AesCtr(enc_prekey_iv[:PREKEY_LEN], enc_prekey_iv[PREKEY_LEN:])
    ks = tg_enc.update(ZERO_64)  # Computes keystream AND advances past 64-byte init

    dec_prekey_iv = enc_prekey_iv[::-1]
    tg_dec = AesCtr(dec_prekey_iv[:PREKEY_LEN], dec_prekey_iv[PREKEY_LEN:])

    tail_plain = proto_tag + struct.pack("<h", dc_idx) + os.urandom(2)
    result = bytearray(rnd_bytes)
    for i in range(8):
        result[PROTO_TAG_POS + i] = tail_plain[i] ^ ks[PROTO_TAG_POS + i]

    return bytes(result), tg_enc, tg_dec


class MsgSplitter:
    """Split a re-encrypted upstream MTProto stream into packet-aligned WS frames."""

    __slots__ = ("_proto_tag", "_cipher_buf", "_plain_buf", "_disabled")

    def __init__(self, proto_tag: bytes):
        self._proto_tag = proto_tag
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._disabled = False

    def split(self, chunk: bytes, plain: bytes) -> list[bytes]:
        if not chunk:
            return []
        if self._disabled:
            return [chunk]

        self._cipher_buf.extend(chunk)
        self._plain_buf.extend(plain)

        parts: list[bytes] = []
        offset = 0
        buf_len = len(self._cipher_buf)
        while offset < buf_len:
            pkt_len = self._next_packet_len(offset, buf_len - offset)
            if pkt_len is None:
                break
            if pkt_len <= 0:
                parts.append(bytes(self._cipher_buf) if offset == 0 else bytes(self._cipher_buf[offset:]))
                offset = buf_len
                self._disabled = True
                break
            parts.append(bytes(self._cipher_buf[offset : offset + pkt_len]))
            offset += pkt_len

        if offset:
            del self._cipher_buf[:offset]
            del self._plain_buf[:offset]
        return parts

    def flush(self) -> list[bytes]:
        if not self._cipher_buf:
            return []
        tail = bytes(self._cipher_buf)
        self._cipher_buf.clear()
        self._plain_buf.clear()
        return [tail]

    def _next_packet_len(self, offset: int, avail: int) -> Optional[int]:
        if avail <= 0:
            return None
        if self._proto_tag == PROTO_TAG_ABRIDGED:
            first = self._plain_buf[offset]
            if first in (0x7F, 0xFF):
                if avail < 4:
                    return None
                payload_len = int.from_bytes(self._plain_buf[offset + 1 : offset + 4], "little") * 4
                hdr_len = 4
            else:
                payload_len = (first & 0x7F) * 4
                hdr_len = 1
            return 0 if payload_len <= 0 else (None if avail < hdr_len + payload_len else hdr_len + payload_len)

        if self._proto_tag in (PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
            if avail < 4:
                return None
            payload_len = struct.unpack_from("<I", self._plain_buf, offset)[0] & 0x7FFFFFFF
            return 0 if payload_len <= 0 else (None if avail < 4 + payload_len else 4 + payload_len)
        return 0


async def read_mtproto_packet(reader, decryptor, proto_tag: bytes) -> Tuple[bytes, bool]:
    """Read and frame one MTProto packet from a decrypted local obfuscated2 stream."""

    async def read_plain(count: int) -> bytes:
        return decryptor.update(await reader.readexactly(count))

    if proto_tag == PROTO_TAG_ABRIDGED:
        first = (await read_plain(1))[0]
        quick = bool(first & 0x80)
        words = first & 0x7F
        if words == 0x7F:
            words = int.from_bytes(await read_plain(3), "little")
        length = words * 4
    else:
        val, = struct.unpack("<I", await read_plain(4))
        quick = bool(val & 0x80000000)
        length = val & 0x7FFFFFFF

    max_allowed = MAX_PACKET + (MAX_PLAIN_PADDING if proto_tag == PROTO_TAG_SECURE else 0)
    if not 24 <= length <= max_allowed:
        raise ValueError(f"MTProto packet length out of range: {length}")

    body = await read_plain(length)
    if proto_tag == PROTO_TAG_SECURE:
        if body[:8] == b"\x00" * 8:
            packet_len = 20 + int.from_bytes(body[16:20], "little")
            max_pad = MAX_PLAIN_PADDING
        else:
            packet_len = 24 + ((length - 24) // 16) * 16
            max_pad = 15
        padding = length - packet_len
        if not 24 <= packet_len <= length or padding > max_pad:
            raise ValueError(
                f"Invalid padded intermediate frame: frame={length} packet={packet_len} pad={padding}"
            )
        body = body[:packet_len]

    if len(body) % 4 or len(body) > MAX_PACKET:
        raise ValueError(f"Invalid MTProto packet alignment or size: {len(body)}")

    return body, quick


def encode_mtproto_reply(body: bytes, proto_tag: bytes) -> bytes:
    """Wrap a raw MTProto response (or 4-byte error) into local client framing."""
    if not body or len(body) % 4 or len(body) > MAX_PACKET:
        raise ValueError(f"Invalid MTProto reply length: {len(body)}")
    if proto_tag == PROTO_TAG_ABRIDGED:
        words = len(body) // 4
        prefix = bytes([words]) if words < 0x7F else b"\x7f" + words.to_bytes(3, "little")
        return prefix + body
    padding = os.urandom(os.urandom(1)[0] % 4) if proto_tag == PROTO_TAG_SECURE else b""
    return struct.pack("<I", len(body) + len(padding)) + body + padding
