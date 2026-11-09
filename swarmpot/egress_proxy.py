#!/usr/bin/env python3
"""Minimal allowlisted CONNECT proxy for model-provider egress.

The attacker container is attached only to internal Docker networks. Its sole
route to the Internet is this proxy, which tunnels only the configured
host:port pairs. TLS is end-to-end; the proxy never sees or modifies model
traffic. This keeps an attacker shell from reaching arbitrary Internet hosts
while still allowing hosted-model calls.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ALLOW = {
    item.strip().lower()
    for item in os.environ.get(
        "SWARMPOT_EGRESS_ALLOW",
        "openrouter.ai:443,api.openai.com:443,api.anthropic.com:443",
    ).split(",")
    if item.strip()
}
LOG_PATH = Path(os.environ.get("SWARMPOT_EGRESS_LOG", "/logs/egress.jsonl"))


def log(record: dict) -> None:
    record["ts"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass


def denied(writer: asyncio.StreamWriter, reason: str, host: str) -> None:
    log({"kind": "denied", "host": host, "reason": reason})
    writer.write(
        (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/plain\r\n"
            f"Content-Length: {len(reason) + 1}\r\n"
            "Connection: close\r\n\r\n"
            f"{reason}\n"
        ).encode()
    )


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=15)
        if not request_line:
            writer.close()
            return
        parts = request_line.decode("latin-1").strip().split(" ")
        if len(parts) < 3:
            denied(writer, "bad request", "")
            await writer.drain()
            writer.close()
            return
        method, target, _version = parts[0].upper(), parts[1], parts[2]

        # Drain request headers (bounded).
        for _ in range(200):
            line = await asyncio.wait_for(reader.readline(), timeout=15)
            if line in (b"\r\n", b"\n", b""):
                break

        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            if not host:
                host, port = target, "443"
            key = f"{host.lower()}:{port}"
            if key not in ALLOW:
                denied(writer, f"egress to {key} is not allowed", host)
                await writer.drain()
                writer.close()
                return
            try:
                up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=20)
            except Exception as exc:
                denied(writer, f"connect failed: {exc}", host)
                await writer.drain()
                writer.close()
                return
            log({"kind": "connect", "host": host, "port": int(port), "allowed": True})
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
            return

        # Plain HTTP proxy requests are not used by the hosted-model clients.
        split = urlsplit(target)
        host = split.hostname or ""
        port = split.port or 80
        key = f"{host.lower()}:{port}"
        if key not in ALLOW:
            denied(writer, f"egress to {key} is not allowed", host)
            await writer.drain()
            writer.close()
            return
        up_reader, up_writer = await asyncio.open_connection(host, port)
        path = split.path or "/"
        if split.query:
            path += "?" + split.query
        up_writer.write(f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        await up_writer.drain()
        log({"kind": "http", "host": host, "port": port, "method": method, "path": path})
        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
    except Exception as exc:
        log({"kind": "error", "error": repr(exc)})
        try:
            writer.close()
        except Exception:
            pass


async def main() -> None:
    port = int(os.environ.get("SWARMPOT_EGRESS_PORT", "3128"))
    server = await asyncio.start_server(handle, "0.0.0.0", port)
    print(f"egress proxy listening on :{port}; allow={sorted(ALLOW)}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
