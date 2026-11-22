"""CLI entry point for FreeTG Ephemeral Carousel MTProto Proxy."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from freetg.server import (
    DEFAULT_SECRET,
    DEFAULT_WORKER_DOMAIN,
    FreeTGConfig,
    FreeTGProxyServer,
)


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="FreeTG — Ephemeral Carousel MTProto Proxy bypassing TSPU freezes"
    )
    ap.add_argument("--host", default="127.0.0.1", help="Listen IP (default: 127.0.0.1)")
    ap.add_argument(
        "--port",
        type=int,
        default=1080,
        help="Primary listen port (default: 1080)",
    )
    ap.add_argument(
        "--extra-port",
        type=int,
        action="append",
        default=[],
        help="Additional listen port(s), e.g. --extra-port 1088",
    )
    ap.add_argument(
        "--secret",
        default=DEFAULT_SECRET,
        help="32-char hex MTProto secret (or 34-char starting with 'dd')",
    )
    ap.add_argument(
        "--worker-domain",
        default=DEFAULT_WORKER_DOMAIN,
        help="Cloudflare Worker domain",
    )
    ap.add_argument(
        "--mode",
        choices=("auto", "v1", "v2"),
        default="auto",
        help="Worker protocol: auto (detect /v2/health), v1 (/apiws), or v2 (/v2/sync)",
    )
    ap.add_argument(
        "--pool-size",
        type=int,
        default=3,
        help="Pre-warmed Worker sockets per active DC (default: 3)",
    )
    ap.add_argument(
        "--frag-tls",
        action="store_true",
        help="Fragment TLS ClientHello records across multiple TCP segments",
    )
    ap.add_argument(
        "--stats-interval",
        type=float,
        default=30.0,
        help="Stats print interval in seconds (0 disables)",
    )
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logs")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-5s  %(message)s",
        datefmt="%H:%M:%S",
    )

    ports = [args.port]
    for p in args.extra_port:
        if p not in ports:
            ports.append(p)

    cfg = FreeTGConfig(
        host=args.host,
        ports=ports,
        secret_hex=args.secret,
        worker_domain=args.worker_domain.strip().removeprefix("https://").removeprefix("http://").rstrip("/"),
        mode=args.mode,
        pool_size=max(1, args.pool_size),
        frag_tls=args.frag_tls,
        stats_interval=args.stats_interval,
        verbose=args.verbose,
    )

    server = FreeTGProxyServer(cfg)
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        logging.getLogger("freetg").info("Stopped by user")
    return 0


if __name__ == "__main__":
    sys.exit(main())
