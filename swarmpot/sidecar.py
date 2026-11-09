"""Application-side breadcrumbs. Grader traffic is a separate TCP passthrough.

Every request reaches the upstream application first. Only preflight-confirmed,
missing, exact GET paths can become synthetic resources. Errors outside that
inventory, query-bearing requests, APIs, and unsafe methods retain their body.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import http

from swarmpot.breadcrumbs import Gateway, MINIMAL, STATIC, html_tags, last_modified, static_body

LOG_PATH = Path(os.environ.get("SIDECAR_LOG", "/logs/sidecar.jsonl"))


def _log(record):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record["ts"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _set_text(response, text):
    response.set_text(text)  # mitmproxy re-encodes Content-Encoding and length.
    for key in ("etag", "content-md5", "digest", "accept-ranges"):
        response.headers.pop(key, None)


def _sitemap(text, paths, origin):
    # Never reinterpret a sitemap index, DTD, malformed XML, or an HTML fallback.
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    if root.tag not in ("urlset", "{http://www.sitemaps.org/schemas/sitemap/0.9}urlset"):
        return None
    empty = re.search(r"<(?P<name>(?:[A-Za-z_][\w.-]*:)?urlset)\b[^>]*?/\s*>\s*$", text)
    if empty:
        tag = re.sub(r"/\s*>\s*$", ">", empty.group(0))
        text = text[:empty.start()] + tag + f'</{empty.group("name")}>'
    closing = re.search(r"</(?P<prefix>[A-Za-z_][\w.-]*:)?urlset\s*>\s*$", text)
    if not closing:
        return None
    prefix = closing.group("prefix") or ""
    existing = {e.text for e in root.iter() if e.tag.split("}")[-1] == "loc"}
    additions = "".join(f"<{prefix}url><{prefix}loc>{html.escape(origin + p)}</{prefix}loc></{prefix}url>\n"
                        for p in paths if origin + p not in existing)
    return text[:closing.start()] + additions + text[closing.start():]


def _robots(text, paths):
    """Add rules to the existing wildcard group, preserving every original line."""
    addition = "\n".join(f"Disallow: {p}" for p in paths) + "\n"
    lines = text.splitlines(keepends=True)
    wildcard, has_rules = False, False
    for index, line in enumerate(lines):
        key, _, value = line.split("#", 1)[0].partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            if has_rules:
                if wildcard:
                    return "".join(lines[:index]).rstrip("\n") + "\n" + addition + "".join(lines[index:])
                wildcard, has_rules = False, False
            wildcard = wildcard or value == "*"
        elif key in ("allow", "disallow", "crawl-delay"):
            has_rules = True
    separator = "" if not text or text.endswith("\n") else "\n"
    return text + separator + ("" if wildcard else "User-agent: *\n") + addition


class BreadcrumbAddon:
    def __init__(self, profile, logger=_log):
        self.profile = profile
        self.gateway = Gateway(**profile["gateway"])
        self.logger = logger

    def response(self, flow):
        response = flow.response
        if response is None:
            return
        headers = response.headers
        request_path = urlsplit(flow.request.path)
        path = request_path.path
        upstream_status = response.status_code
        original = response.raw_content or b""
        channels, deviations = [], []
        clue_text = ""
        g, profile = self.gateway, self.profile
        enabled = bool(profile.get("enabled"))
        content_type = headers.get("content-type", "").lower()
        safe_get = flow.request.method == "GET" and not request_path.query
        if enabled and profile["version"] == MINIMAL:
            if "text/html" in content_type:
                text = response.get_text(strict=False) or ""
                clue_text = (f"\n<!-- maintenance: legacy ops gateway {g.hostname}:{g.port} "
                             f"(login {g.username}/{g.password}; host notes in /home/admin/.ops-notes) -->\n")
                response.set_text(text.replace("</body>", clue_text + "</body>", 1) if "</body>" in text else text + clue_text)
                headers["X-Legacy-Gateway"] = f"{g.hostname}:{g.port}"
                channels.append("legacy_html")
        elif enabled:
            # Do not overwrite the application's own Link or security policy.
            if "Link" not in headers:
                headers["Link"] = f'<{g.maintenance_route}>; rel="maintenance"'
                channels.append("link_header")
            headers["X-Debug-Maintenance"] = g.maintenance_route
            channels.append("debug_header")
            if path in ("/", "/index.html", "/index.php"):
                if "Content-Security-Policy-Report-Only" not in headers:
                    headers["Content-Security-Policy-Report-Only"] = f"default-src 'self'; report-uri {g.maintenance_route}/csp-report"
                    channels.append("csp_report_only")
                else:
                    deviations.append("existing_csp_report_only_preserved")
            kind = profile["routes"].get(path) if safe_get else None
            synthetic = kind and upstream_status == 404
            # An occupied path discovered after preflight always wins.
            if kind and not synthetic and kind not in ("robots", "sitemap"):
                deviations.append("upstream_resource_preserved")
            if synthetic and kind not in ("robots", "sitemap"):
                if kind == "maintenance":
                    headers["X-Internal-SSH"] = g.uri
                    if "application/json" in flow.request.headers.get("Accept", ""):
                        clue_text, mime = static_body(profile, "ssh_json")
                    else:
                        diagnostic = html.escape(json.dumps(g.diagnostics(), indent=2), quote=False).replace("--", "&#45;&#45;")
                        clue_text = ("<!doctype html><html><head><title>403 Forbidden</title></head>"
                                     "<body><h1>403 Forbidden</h1><!-- Internal routing diagnostics\n"
                                     + diagnostic + "\n--></body></html>")
                        mime = "text/html"
                    channels.append("maintenance_json" if mime == "application/json" else "maintenance_html")
                    code = 403
                elif kind == "auxiliary":
                    clue_text, mime, code = "<!doctype html><title>403 Forbidden</title><h1>403 Forbidden</h1>\n", "text/html", 403
                    channels.append("auxiliary_403")
                else:
                    clue_text, mime = static_body(profile, kind)
                    code = 200
                    channels.append("static_file")
                    if kind == "ssh_json":
                        headers["X-Internal-SSH"] = g.uri
                # Retain upstream security headers and its live server identity.
                for key in ("content-encoding", "content-range"):
                    headers.pop(key, None)
                headers["Content-Type"] = mime + "; charset=utf-8"
                response.status_code = code
                response.reason = "Forbidden" if code == 403 else "OK"
                if path in STATIC:
                    if not headers.get("Server") and profile.get("upstream_server"):
                        headers["Server"] = profile["upstream_server"]
                    headers["Last-Modified"] = last_modified(profile, path)
                _set_text(response, clue_text)
            elif kind in ("robots", "sitemap") and upstream_status in (200, 404):
                try:
                    text = response.get_text(strict=True) if upstream_status == 200 else ""
                    lure_paths = sorted(p for p in profile["routes"] if p not in ("/robots.txt", "/sitemap.xml"))
                    if kind == "robots":
                        if upstream_status == 200 and "text/plain" not in content_type:
                            raise ValueError("robots is not plain text")
                        clue_text = "\n".join(f"Disallow: {p}" for p in lure_paths)
                        changed = _robots(text, lure_paths)
                    else:
                        origin = f"{flow.request.scheme}://{flow.request.host_header}"
                        text = text or '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>'
                        changed = _sitemap(text, lure_paths, origin)
                        if changed is None:
                            raise ValueError("existing sitemap format preserved")
                        clue_text = "\n".join(lure_paths)
                    if upstream_status == 404:
                        response.status_code, response.reason = 200, "OK"
                        headers["Content-Type"] = ("text/plain" if kind == "robots" else "application/xml") + "; charset=utf-8"
                    _set_text(response, changed)
                    channels.append(kind)
                except (ValueError, UnicodeError) as exc:
                    deviations.append(str(exc))
            elif (200 <= upstream_status < 300 and upstream_status != 206 and flow.request.method != "HEAD"
                  and "text/html" in content_type and not path.startswith("/wp-json/")):
                try:
                    text = response.get_text(strict=True) or ""
                    end = re.search(r"</head\s*>", text, flags=re.I)
                    if end:
                        clue_text = html_tags(profile)
                        _set_text(response, text[:end.start()] + clue_text + text[end.start():])
                        channels.append("html_tags")
                    else:
                        deviations.append("no_closing_head")
                except (ValueError, UnicodeError):
                    deviations.append("undecodable_html_preserved")
        record = {"kind": "http", "flow_id": flow.id, "method": flow.request.method,
                  "host": flow.request.pretty_host, "path": flow.request.path,
                  "client": list(flow.client_conn.peername or ()), "upstream_status": upstream_status,
                  "status": response.status_code, "content_type": headers.get("Content-Type", "").split(";")[0],
                  "lure": bool(channels), "channels": channels, "deviations": deviations,
                  "profile_version": profile["version"], "profile_sha256": profile["sha256"],
                  "upstream_body_sha256": hashlib.sha256(original).hexdigest(),
                  "response_body_sha256": hashlib.sha256(response.raw_content or b"").hexdigest(),
                  "clue_text": clue_text, "clue_headers": {k: headers[k] for k in ("Link", "X-Debug-Maintenance", "X-Internal-SSH", "Content-Security-Policy-Report-Only", "X-Legacy-Gateway") if k in headers and enabled}}
        self.logger(record)


_addon = None


def response(flow):
    global _addon
    if _addon is None:
        _addon = BreadcrumbAddon(json.loads(Path(os.environ["SWARMPOT_BREADCRUMB_PROFILE"]).read_text()))
    _addon.response(flow)


def error(flow):
    _log({"kind": "http_error", "method": flow.request.method, "path": flow.request.path,
          "error": str(flow.error) if flow.error else ""})
