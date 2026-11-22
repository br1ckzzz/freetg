import { connect } from "cloudflare:sockets";

// FreeTG Stealth Cloudflare Worker v2
// Supports:
//   1. GET  /apiws?dst=<DC_IP>&dc=<DC>   (backward-compatible WebSocket TCP tunnel for V1 carousel)
//   2. GET  /v2/health                   (capability probe for FreeTG client)
//   3. POST /v2/sync?dst=<DC_IP>         (stateless HTTP MTProto proxy over cloudflare:sockets + 6KB slicing)
//   4. GET  /v2/slice?id=<ID>&off=<N>&len=<M> (fetch subsequent 6KB response slices across fresh TCP sockets)

const SLICE_SIZE = 6144;
const SLICE_TTL_MS = 45000;
const sliceStore = new Map();

function gcSlices() {
  const now = Date.now();
  for (const [k, v] of sliceStore.entries()) {
    if (now - v.ts > SLICE_TTL_MS) {
      sliceStore.delete(k);
    }
  }
}

function isAllowedTelegramHost(dst) {
  if (!dst) return false;
  return /^(149\.154\.|91\.105\.|91\.108\.|95\.161\.)\d{1,3}\.\d{1,3}$/.test(dst);
}

function toBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data && typeof data.arrayBuffer === "function") {
    return data.arrayBuffer().then((ab) => new Uint8Array(ab));
  }
  return new Uint8Array();
}

function findHeaderEnd(buf) {
  for (let i = 0; i <= buf.length - 4; i++) {
    if (buf[i] === 13 && buf[i + 1] === 10 && buf[i + 2] === 13 && buf[i + 3] === 10) {
      return i;
    }
  }
  return -1;
}

function concatBytes(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function decodeChunked(raw) {
  const parts = [];
  let pos = 0;
  while (pos < raw.length) {
    let lineEnd = -1;
    for (let i = pos; i <= raw.length - 2; i++) {
      if (raw[i] === 13 && raw[i + 1] === 10) {
        lineEnd = i;
        break;
      }
    }
    if (lineEnd === -1) return null;
    const sizeStr = new TextDecoder().decode(raw.subarray(pos, lineEnd)).split(";")[0].trim();
    const size = parseInt(sizeStr, 16);
    if (Number.isNaN(size)) return null;
    pos = lineEnd + 2;
    if (size === 0) {
      if (pos + 2 <= raw.length) return concatBytes(parts);
      return null;
    }
    if (pos + size + 2 > raw.length) return null;
    parts.push(raw.subarray(pos, pos + size));
    pos += size + 2;
  }
  return null;
}

async function postToTelegramDc(dst, mtBody) {
  const socket = connect({ hostname: dst, port: 443 });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  try {
    const reqHeaders = new TextEncoder().encode(
      `POST /api HTTP/1.1\r\n` +
      `Host: ${dst}\r\n` +
      `Content-Type: application/octet-stream\r\n` +
      `Content-Length: ${mtBody.length}\r\n` +
      `Connection: close\r\n\r\n`
    );
    const fullReq = concatBytes([reqHeaders, mtBody]);
    await writer.write(fullReq);

    const chunks = [];
    let totalLen = 0;
    let headerEnd = -1;
    let status = 502;
    let contentLength = -1;
    let isChunked = false;

    while (true) {
      const { value, done } = await reader.read();
      if (value && value.length > 0) {
        chunks.push(value);
        totalLen += value.length;
      }
      const joined = concatBytes(chunks);
      if (headerEnd === -1) {
        headerEnd = findHeaderEnd(joined);
        if (headerEnd !== -1) {
          const hdrText = new TextDecoder().decode(joined.subarray(0, headerEnd));
          const lines = hdrText.split("\r\n");
          const firstParts = lines[0].split(" ");
          status = parseInt(firstParts[1] || "502", 10);
          for (let i = 1; i < lines.length; i++) {
            const idx = lines[i].indexOf(":");
            if (idx === -1) continue;
            const k = lines[i].slice(0, idx).trim().toLowerCase();
            const v = lines[i].slice(idx + 1).trim();
            if (k === "content-length") contentLength = parseInt(v, 10);
            if (k === "transfer-encoding" && v.toLowerCase().includes("chunked")) isChunked = true;
          }
        }
      }
      if (headerEnd !== -1) {
        const bodySlice = joined.subarray(headerEnd + 4);
        if (contentLength >= 0 && bodySlice.length >= contentLength) {
          return { status, body: bodySlice.subarray(0, contentLength) };
        }
        if (isChunked) {
          const decoded = decodeChunked(bodySlice);
          if (decoded !== null) {
            return { status, body: decoded };
          }
        }
      }
      if (done) {
        if (headerEnd !== -1) {
          return { status, body: joined.subarray(headerEnd + 4) };
        }
        throw new Error("Incomplete HTTP response from Telegram DC");
      }
      if (totalLen > 4 * 1024 * 1024) {
        throw new Error("Response exceeded 4MB bound");
      }
    }
  } finally {
    try { reader.releaseLock(); } catch {}
    try { writer.releaseLock(); } catch {}
    try { socket.close(); } catch {}
  }
}

function handleWebSocket(request) {
  const url = new URL(request.url);
  if (url.pathname !== "/apiws") {
    return new Response("Not found", { status: 404 });
  }
  const dst = url.searchParams.get("dst");
  if (!isAllowedTelegramHost(dst)) {
    return new Response("Forbidden dst", { status: 403 });
  }

  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();

  const socket = connect({ hostname: dst, port: 443 });
  const tcpReader = socket.readable.getReader();
  const tcpWriter = socket.writable.getWriter();

  server.addEventListener("message", async (event) => {
    try {
      await tcpWriter.write(await toBytes(event.data));
    } catch {
      try { server.close(1011, "tcp write failed"); } catch {}
    }
  });

  server.addEventListener("close", async () => {
    try { await tcpWriter.close(); } catch {}
    try { socket.close(); } catch {}
  });

  (async () => {
    try {
      while (true) {
        const { value, done } = await tcpReader.read();
        if (done) break;
        if (value) server.send(value);
      }
    } catch {
    } finally {
      try { server.close(); } catch {}
      try { tcpReader.releaseLock(); } catch {}
      try { socket.close(); } catch {}
    }
  })();

  return new Response(null, { status: 101, webSocket: client });
}

export default {
  async fetch(request) {
    if ((request.headers.get("Upgrade") || "").toLowerCase() === "websocket") {
      return handleWebSocket(request);
    }

    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/v2/health") {
      return new Response(JSON.stringify({ ok: true, mode: "freetg-v2", slice: SLICE_SIZE }), {
        status: 200,
        headers: { "content-type": "application/json", "cache-control": "no-store" },
      });
    }

    if (request.method === "POST" && url.pathname === "/v2/sync") {
      const dst = url.searchParams.get("dst");
      if (!isAllowedTelegramHost(dst)) {
        return new Response("Forbidden dst", { status: 403 });
      }
      const reqBytes = new Uint8Array(await request.arrayBuffer());
      const { status, body } = await postToTelegramDc(dst, reqBytes);

      if (body.length <= SLICE_SIZE) {
        return new Response(body, {
          status,
          headers: {
            "content-type": "application/octet-stream",
            "x-total-len": String(body.length),
            "cache-control": "no-store",
          },
        });
      }

      gcSlices();
      const sliceId = crypto.randomUUID();
      sliceStore.set(sliceId, { data: body, ts: Date.now() });

      const firstChunk = body.subarray(0, SLICE_SIZE);
      return new Response(firstChunk, {
        status: 206,
        headers: {
          "content-type": "application/octet-stream",
          "x-slice-id": sliceId,
          "x-total-len": String(body.length),
          "x-slice-offset": "0",
          "cache-control": "no-store",
        },
      });
    }

    if (request.method === "GET" && url.pathname === "/v2/slice") {
      const id = url.searchParams.get("id");
      const off = parseInt(url.searchParams.get("off") || "0", 10);
      const len = Math.min(SLICE_SIZE, parseInt(url.searchParams.get("len") || String(SLICE_SIZE), 10));
      const entry = sliceStore.get(id);
      if (!entry) {
        return new Response("Slice expired or isolate miss", { status: 404 });
      }
      const end = Math.min(entry.data.length, off + len);
      if (end >= entry.data.length) {
        sliceStore.delete(id);
      }
      return new Response(entry.data.subarray(off, end), {
        status: 200,
        headers: {
          "content-type": "application/octet-stream",
          "x-total-len": String(entry.data.length),
          "x-slice-offset": String(off),
          "cache-control": "no-store",
        },
      });
    }

    return new Response("OK", { status: 200 });
  },
};
