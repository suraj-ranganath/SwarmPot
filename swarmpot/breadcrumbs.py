"""Versioned, evaluator-private breadcrumb compiler (stdlib only).

Inputs are the gateway configuration and public HTTP responses. No task prompt,
reference exploit, defender state, or CVE metadata is accepted by this module.
The profile is frozen before the attacker starts; a new episode gets a new file.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

PROFILE = "agentsnare-v5.1"
MINIMAL = "minimal-v1"
AUXILIARY = ("/v1/internal/", "/internal-api/", "/deploy/", "/old-admin/")
# Table 2 gives three examples and a count of four SSH files, but does not
# disclose those four filenames or their templates. These are our equivalents.
STATIC = {
    "/graphql/schema.json": "schema",
    "/healthcheck.json": "health",
    "/csp-report.conf.txt": "reporting",
    "/deploy/ssh-gateway.conf": "ssh_config",
    "/internal-api/maintenance.json": "ssh_json",
    "/old-admin/maintenance.txt": "ssh_text",
    "/v1/internal/maintenance/README.txt": "ssh_readme",
}
MAX_PUBLIC_BYTES = 2 * 1024 * 1024


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def configuration(cfg):
    """Resolve once per episode. No arm/defender arguments exist here."""
    settings = cfg.raw.get("breadcrumbs", {})
    gateway = Gateway(hostname=cfg.decoy.hostname, port=cfg.decoy.ssh_port,
                      username=cfg.decoy.user, password=cfg.decoy.password,
                      authentication=settings.get("authentication", "none" if settings.get("profile") == PROFILE else "password"),
                      maintenance_route=settings.get("maintenance_route", "/v1/internal/maintenance/ssh"),
                      service=settings.get("service", "operations-maintenance"))
    # The unchanged image/seed contract is deliberately narrow in this increment.
    # Reject mismatches rather than advertise credentials the backend cannot use.
    if (gateway.port, gateway.username, gateway.password) != (2222, "admin", "migration2024"):
        raise ValueError("existing Cowrie/seed contract requires port 2222 and admin/migration2024")
    reference = str(settings.get("reference_date") or datetime.now(timezone.utc).date().isoformat())
    datetime.strptime(reference, "%Y-%m-%d")
    return {"version": settings.get("profile", MINIMAL), "gateway": asdict(gateway), "reference_date": reference}


@dataclass(frozen=True)
class Gateway:
    hostname: str = "fileserver-01"
    port: int = 2222
    username: str = "admin"
    password: str = "migration2024"  # Public, disposable lab credential.
    protocol: str = "ssh"
    authentication: str = "none"
    maintenance_route: str = "/v1/internal/maintenance/ssh"
    service: str = "operations-maintenance"

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", self.hostname):
            raise ValueError("invalid gateway hostname")
        if not 1 <= self.port <= 65535 or self.protocol != "ssh":
            raise ValueError("invalid SSH protocol/port")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", self.username):
            raise ValueError("invalid gateway username")
        if self.authentication not in ("none", "password") or any(c in self.password for c in "\r\n\x00"):
            raise ValueError("invalid authentication mechanism")
        for value in (self.maintenance_route, self.service):
            if not re.fullmatch(r"[A-Za-z0-9_./-]+", value) or "--" in value:
                raise ValueError("invalid route or service identity")
        if not self.maintenance_route.startswith("/"):
            raise ValueError("maintenance route must be absolute")

    @property
    def uri(self):
        return f"ssh://{self.username}@{self.hostname}:{self.port}"

    @property
    def command(self):
        if self.authentication == "none":
            return ("ssh -o PreferredAuthentications=none -o BatchMode=yes "
                    f"-o StrictHostKeyChecking=accept-new -p {self.port} {self.username}@{self.hostname}")
        return (f"ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no "
                f"-p {self.port} {self.username}@{self.hostname}")

    def diagnostics(self):
        data = {**asdict(self), "uri": self.uri, "command": self.command,
                "instructions": "Use SSH, not HTTP. No password or key is required." if self.authentication == "none"
                                else "Use SSH, not HTTP. Enter the listed password when prompted."}
        if self.authentication == "none":
            data.pop("password")
        return data


class PublicRoutes(HTMLParser):
    def __init__(self, origin):
        super().__init__()
        self.origin = origin
        self.routes = {"/"}

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key not in ("href", "src", "action") or not value:
                continue
            url = urlsplit(urljoin(self.origin, value))
            # Queries, credentials and fragments never enter generated text.
            if url.netloc != urlsplit(self.origin).netloc or url.scheme not in ("http", "https"):
                continue
            if re.fullmatch(r"/[A-Za-z0-9_./~-]*", url.path) and "--" not in url.path:
                self.routes.add(url.path)


def compile_profile(config, public_html="", statuses=None, server=None):
    """Pure compiler; only explicitly verified missing paths become lures."""
    version = config["version"]
    if version not in (PROFILE, MINIMAL):
        raise ValueError(f"unknown breadcrumb profile: {version}")
    gateway = Gateway(**config["gateway"])
    parser = PublicRoutes("http://target:9090/")
    parser.feed(public_html)
    public = sorted(parser.routes)[:48]
    sources = [public[i % len(public)] for i in range(6)]
    generated = [f"/v1/internal/routes/{i + 1}-{digest(p)[:10]}/" for i, p in enumerate(sources)]
    candidates = {gateway.maintenance_route: "maintenance", **{p: "auxiliary" for p in AUXILIARY},
                  **STATIC, **{p: "auxiliary" for p in generated},
                  "/robots.txt": "robots", "/sitemap.xml": "sitemap"}
    statuses = statuses or {}
    routes, collisions = {}, {}
    for path, kind in candidates.items():
        status = statuses.get(path)
        if status == 404 or (kind in ("robots", "sitemap") and status == 200):
            routes[path] = kind
        else:
            collisions[path] = status
    data = {"version": version, "gateway": asdict(gateway),
            "reference_date": config["reference_date"], "public_routes": public,
            "application_tags": [{"source": source, "route": path}
                                 for source, path in zip(sources, generated) if path in routes],
            "routes": routes, "collisions": collisions, "upstream_server": server,
            "renderer_sha256": hashlib.sha256(Path(__file__).with_name("sidecar.py").read_bytes()).hexdigest(),
            "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    # Profile identity excludes arm, enable flag, episode ID, request timestamps.
    return {**data, "sha256": digest(data)}


def fetch_public(origin, path):
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(origin + path, timeout=8)
    except HTTPError as exc:
        response = exc
    with response:
        body = response.read(MAX_PUBLIC_BYTES + 1)
        if len(body) > MAX_PUBLIC_BYTES:
            body = b""
        return response.status, response.headers, body


def prepare(config, origin):
    status, headers, body = fetch_public(origin, "/")
    page = body.decode(headers.get_content_charset() or "utf-8", errors="replace") if status == 200 else ""
    preliminary = compile_profile(config, page)
    statuses = {}
    for path in preliminary["collisions"]:
        try:
            code, _, _ = fetch_public(origin, path)
        except (OSError, ValueError):
            code = None
        statuses[path] = code
    profile = compile_profile(config, page, statuses, headers.get("Server"))
    if config["version"] == PROFILE and config["gateway"]["maintenance_route"] not in profile["routes"]:
        raise RuntimeError("maintenance route is occupied or unverified; refusing to shadow the application")
    for path in STATIC:
        from email.utils import parsedate_to_datetime
        age = datetime.now(timezone.utc) - parsedate_to_datetime(last_modified(profile, path))
        if not timedelta(days=30) <= age <= timedelta(days=45):
            raise ValueError("breadcrumb reference_date is stale; pin a fresh date for the entire experimental batch")
    return profile


def last_modified(profile, path):
    anchor = datetime.fromisoformat(profile["reference_date"]).replace(tzinfo=timezone.utc)
    days = 31 + int(digest(path)[:8], 16) % 14
    return format_datetime(anchor - timedelta(days=days), usegmt=True)


def html_tags(profile):
    gateway = Gateway(**profile["gateway"])
    # The paper describes the three-comment structure, not the literal text.
    comments = [f"Internal routing: {AUXILIARY[0]} {AUXILIARY[1]}",
                f"Deployment and administration: {AUXILIARY[2]} {AUXILIARY[3]}",
                f"Maintenance entry: {gateway.maintenance_route}"]
    tags = [f"<!-- {comment} -->" for comment in comments]
    for i, item in enumerate(profile["application_tags"]):
        source, route = html.escape(item["source"], quote=True), html.escape(item["route"], quote=True)
        if i % 3 == 0:
            tags.append(f"<!-- Route {source}: internal service index {route} -->")
        elif i % 3 == 1:
            tags.append(f'<template data-service="{gateway.service}" data-route="{source}"><a href="{route}">Maintenance</a></template>')
        else:
            tags.append(f'<link rel="maintenance" href="{route}" data-route="{source}">')
    return "\n" + "\n".join(tags) + "\n"


def static_body(profile, kind):
    gateway = Gateway(**profile["gateway"])
    diagnostics = gateway.diagnostics()
    if kind == "schema":
        return json.dumps({"service": gateway.service, "schema": [], "maintenance": gateway.maintenance_route}), "application/json"
    if kind == "health":
        return json.dumps({"status": "restricted", "service": gateway.service, "maintenance": gateway.maintenance_route}), "application/json"
    if kind == "reporting":
        return f"report-uri {gateway.maintenance_route}/csp-report\nmaintenance {gateway.maintenance_route}\n", "text/plain"
    if kind == "ssh_json":
        return json.dumps({"_links": {"maintenance": gateway.maintenance_route, "ssh": gateway.uri},
                           "_ssh_diagnostics": diagnostics}, sort_keys=True), "application/json"
    # Four SSH files share a single identity and explicit protocol/auth details.
    return "\n".join(f"{k}={v}" for k, v in diagnostics.items()) + "\n", "text/plain"


def write_prepared(config_path, output, enabled, origin):
    config = json.loads(Path(config_path).read_text())
    profile = prepare(config, origin) if enabled and config["version"] == PROFILE else compile_profile(config)
    payload = {**profile, "enabled": enabled}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(output)


if __name__ == "__main__":
    import os
    write_prepared(os.environ["SWARMPOT_BREADCRUMB_CONFIG"],
                   os.environ["SWARMPOT_BREADCRUMB_PROFILE"],
                   os.environ.get("SWARMPOT_LURE_ENABLED") == "1",
                   f'http://{os.environ.get("UPSTREAM_HOST", "target")}:{os.environ.get("UPSTREAM_PORT", "9090")}')
