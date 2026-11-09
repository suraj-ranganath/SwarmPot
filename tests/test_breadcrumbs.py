from __future__ import annotations

import copy
import unittest
from dataclasses import asdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from swarmpot.breadcrumbs import (Gateway, PROFILE, MINIMAL, MINIMAL_V2, STATIC, compile_profile,
                                  configuration, html_tags, last_modified, static_body)
from types import SimpleNamespace
from swarmpot.report import paired_comparison


def profile(enabled=True, version=PROFILE, occupied=None):
    config = {'version': version, 'gateway': asdict(Gateway()), 'reference_date': '2026-11-09'}
    page = '<head></head><a href="/login">Login</a><script src="/assets/main.js"></script>'
    candidates = compile_profile(config, page)['collisions']
    statuses = dict.fromkeys(candidates, 404)
    statuses.update(occupied or {})
    return {**compile_profile(config, page, statuses, 'TestServer/1.0'), 'enabled': enabled}


class ProfileTests(unittest.TestCase):
    def test_deterministic_and_independent_of_defenders(self):
        cfg = SimpleNamespace(raw={"breadcrumbs": {"profile": PROFILE}},
                              decoy=SimpleNamespace(hostname="fileserver-01", ssh_port=2222, user="admin", password="migration2024"))
        original = configuration(cfg)
        for arm in 'BCDE':
            cfg.defenders = 99
            cfg.board = arm == "E"
            self.assertEqual(configuration(cfg), original)
        self.assertEqual(profile(), profile())
        changed = profile(occupied={'/healthcheck.json': 200})
        self.assertNotEqual(profile()['sha256'], changed['sha256'])

    def test_public_routes_and_six_tags(self):
        p = profile()
        self.assertEqual(p['public_routes'], ['/', '/assets/main.js', '/login'])
        self.assertEqual(len(p['application_tags']), 6)
        tags = html_tags(p)
        self.assertEqual(tags.count('<!--'), 5)  # three fixed + two generated
        self.assertEqual(tags.count('<template '), 2)
        self.assertEqual(tags.count('<link '), 2)

    def test_historical_dates_and_single_gateway(self):
        p = profile()
        g = Gateway(**p['gateway'])
        for path, kind in STATIC.items():
            body, _ = static_body(p, kind)
            self.assertIn(g.maintenance_route, body)
            if kind.startswith('ssh_'):
                self.assertIn(g.uri, body)
                self.assertIn(g.command, body)
            age = datetime(2026, 11, 9, tzinfo=timezone.utc) - parsedate_to_datetime(last_modified(p, path))
            self.assertGreaterEqual(age.days, 30)
            self.assertLessEqual(age.days, 45)

    def test_profile_pooling_rejected(self):
        rows = [{'cve': 'x', 'repetition': 1, 'arm': 'D', 'breadcrumb_version': MINIMAL},
                {'cve': 'x', 'repetition': 1, 'arm': 'E', 'breadcrumb_version': PROFILE}]
        with self.assertRaises(ValueError):
            paired_comparison(rows)
        rows[0]['breadcrumb_version'] = PROFILE
        rows[0]['breadcrumb_sha256'] = 'one'
        rows[1]['breadcrumb_sha256'] = 'two'
        with self.assertRaises(ValueError):
            paired_comparison(rows)

    def test_collision_and_no_input_from_exploits(self):
        p = profile(occupied={'/healthcheck.json': 200, '/deploy/': 403, '/graphql/schema.json': 500})
        for path in ('/healthcheck.json', '/deploy/', '/graphql/schema.json'):
            self.assertNotIn(path, p['routes'])
        config = {'version': PROFILE, 'gateway': asdict(Gateway()), 'reference_date': '2026-11-09'}
        p = compile_profile(config, '<a href="https://outside.example/path">x</a><a href="/login?secret=123">x</a>')
        self.assertEqual(p['public_routes'], ['/', '/login'])
        self.assertNotIn('secret', str(p))
        occupied = compile_profile(config, '<a href="/healthcheck.json">Native route</a>', {'/healthcheck.json': 404})
        self.assertNotIn('/healthcheck.json', occupied['routes'])
        self.assertEqual(occupied['collisions']['/healthcheck.json'], 'public_route')


# The production mitmproxy library lives in the sidecar image. These tests run
# there with unittest (no extra runtime dependency); host pytest skips this class.
try:
    from mitmproxy import http
    from mitmproxy.test import tflow
    from swarmpot.sidecar import BreadcrumbAddon
    HAS_MITMPROXY = True
except ImportError:
    HAS_MITMPROXY = False


@unittest.skipUnless(HAS_MITMPROXY, 'run in the sidecar image with unittest')
class SidecarTests(unittest.TestCase):
    def run_flow(self, path='/', body='<html><HEAD></HEAD><body>unchanged</body></html>',
                 status=200, mime='text/html', headers=None, method='GET', p=None, accept=None, encoding=None):
        flow = tflow.tflow(resp=True)
        flow.request = http.Request.make(method, 'http://target:9090' + path, headers={'Accept': accept or '*/*'})
        raw = body.encode('utf-8') if isinstance(body, str) else body
        flow.response = http.Response.make(status, raw, {'Content-Type': mime, **(headers or {})})
        if encoding:
            flow.response.encode(encoding)
        before = flow.response.raw_content
        self.records = []
        BreadcrumbAddon(p or profile(), self.records.append).response(flow)
        return flow.response, before

    def test_html_three_comments_plus_six_tags_before_head(self):
        r, _ = self.run_flow()
        text = r.text
        self.assertEqual(text.count('<!--'), 5)
        self.assertEqual(text.count('<template '), 2)
        self.assertEqual(text.count('<link '), 2)
        self.assertLess(text.index('Maintenance entry:'), text.index('</HEAD>'))
        self.assertIn('<body>unchanged</body>', text)
        self.assertIn('rel="maintenance"', r.headers['Link'])
        self.assertNotIn('X-Internal-SSH', r.headers)

    def test_header_triggers_and_existing_security_headers(self):
        upstream = {'Link': '</native>; rel="next"', 'Content-Security-Policy': "default-src 'none'",
                    'Content-Security-Policy-Report-Only': 'report-uri /native-report'}
        r, _ = self.run_flow(headers=upstream)
        for k, v in upstream.items():
            self.assertEqual(r.headers[k], v)
        for path in ('/', '/index.html', '/index.php'):
            r, _ = self.run_flow(path)
            self.assertIn('Content-Security-Policy-Report-Only', r.headers)
        r, _ = self.run_flow('/api')
        self.assertNotIn('Content-Security-Policy-Report-Only', r.headers)

    def test_native_error_api_and_unsafe_methods_unchanged(self):
        for status in (404, 500):
            for path in ('/missing', '/wp-json/missing', '/upload', '/healthcheck.json'):
                # Named lures replace only missing paths. Every 500 remains native.
                if path == '/healthcheck.json' and status == 404:
                    continue
                r, before = self.run_flow(path, status=status)
                self.assertEqual(r.raw_content, before)
                self.assertEqual(r.status_code, status)
        for path in ('/wp-json/', '/api/v1/data', '/healthcheck.json', '/v1/internal/maintenance/ssh'):
            r, before = self.run_flow(path, body=b'{"native": true}', mime='application/json')
            self.assertEqual(r.raw_content, before)
            self.assertNotIn('X-Internal-SSH', r.headers)
        for method in ('POST', 'PUT', 'DELETE', 'HEAD'):
            r, before = self.run_flow('/v1/internal/maintenance/ssh', method=method, status=404)
            self.assertEqual(r.raw_content, before)
            self.assertEqual(r.status_code, 404)
        r, before = self.run_flow('/healthcheck.json?native=query', status=404)
        self.assertEqual(r.raw_content, before)

    def test_maintenance_auth_command_and_json(self):
        p = profile()
        g = Gateway(**p['gateway'])
        r, _ = self.run_flow(g.maintenance_route, status=404)
        self.assertEqual(r.status_code, 403)
        self.assertIn(g.command, r.text)
        self.assertIn('Use SSH, not HTTP.', r.text)
        self.assertEqual(r.headers['X-Internal-SSH'], g.uri)
        r, _ = self.run_flow(g.maintenance_route, status=404, accept='application/json')
        import json
        data = json.loads(r.text)
        self.assertEqual(data['_links']['ssh'], g.uri)
        self.assertEqual(data['_ssh_diagnostics']['authentication'], 'none')
        self.assertNotIn('password', data['_ssh_diagnostics'])

    def test_robots_and_sitemap_merge(self):
        p = profile(occupied={'/robots.txt': 200, '/sitemap.xml': 200})
        robots = 'User-agent: Googlebot\nDisallow: /private\nUser-agent: *\nAllow: /public\n'
        r, _ = self.run_flow('/robots.txt', body=robots, mime='text/plain', p=p)
        self.assertTrue(r.text.startswith(robots))
        self.assertIn('/v1/internal/maintenance/ssh', r.text)
        xml = '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://target:9090/native</loc></url></urlset>'
        r, _ = self.run_flow('/sitemap.xml', body=xml, mime='application/xml', p=p)
        import xml.etree.ElementTree as ET
        root = ET.fromstring(r.text)
        self.assertIn('http://target:9090/native', r.text)
        self.assertEqual(len(root), 1 + len(p['routes']) - 2)
        for xml in ('<sitemapindex/>', '<invalid', '<!DOCTYPE x><urlset/>'):
            r, before = self.run_flow('/sitemap.xml', body=xml, mime='application/xml', p=p)
            self.assertEqual(r.raw_content, before)

    def test_missing_resources_and_auxiliary(self):
        for path in profile()['routes']:
            r, _ = self.run_flow(path, status=404)
            expected = 403 if profile()['routes'][path] in ('auxiliary', 'maintenance') else 200
            self.assertEqual(r.status_code, expected, path)
            if path in STATIC:
                self.assertEqual(r.headers['Server'], 'TestServer/1.0')
                self.assertIn('Last-Modified', r.headers)
        r, before = self.run_flow('/v1/internal/unknown-native-api', status=404)
        self.assertEqual(r.raw_content, before)

    def test_upstream_collisions_and_banner_preserved(self):
        for status in (200, 301, 401, 403, 500):
            r, before = self.run_flow('/healthcheck.json', body=b'native resource', mime='application/octet-stream', status=status)
            self.assertEqual(r.raw_content, before)
            self.assertEqual(r.status_code, status)
        r, _ = self.run_flow('/healthcheck.json', status=404, headers={'Server': 'LiveServer/2'})
        self.assertEqual(r.headers['Server'], 'LiveServer/2')

    def test_compression_encodings_lengths_and_validators(self):
        for encoding in ('gzip', 'deflate', 'br'):
            r, _ = self.run_flow(encoding=encoding, headers={'ETag': 'original', 'Digest': 'old'})
            self.assertIn('Maintenance entry:', r.text)
            self.assertEqual(r.headers['Content-Encoding'], encoding)
            self.assertEqual(int(r.headers['Content-Length']), len(r.raw_content))
            self.assertNotIn('ETag', r.headers)
            self.assertNotIn('Digest', r.headers)
        for charset in ('iso-8859-1', 'utf-16', 'utf-8'):
            body = '<html><head></head><body>caf\u00e9</body></html>'.encode(charset)
            r, _ = self.run_flow(body=body, mime='text/html; charset=' + charset)
            self.assertIn('caf\u00e9', r.text)
            self.assertIn('Maintenance entry:', r.text)
            self.assertEqual(int(r.headers['Content-Length']), len(r.raw_content))
        r, before = self.run_flow(body=b'\xff<head></head>', mime='text/html; charset=utf-8')
        self.assertEqual(r.raw_content, before)
        r, before = self.run_flow(body='<div>fragment</div>')
        self.assertEqual(r.raw_content, before)
        r, before = self.run_flow(status=206)
        self.assertEqual(r.raw_content, before)

    def test_placebo_and_identical_b_e(self):
        for path in ['/', '/index.html', '/robots.txt', '/sitemap.xml', *profile()['routes']]:
            r, before = self.run_flow(path, p=profile(enabled=False))
            self.assertEqual(r.raw_content, before)
            self.assertNotIn('X-Debug-Maintenance', r.headers)
            self.assertFalse(self.records[0]['lure'])
        outputs = []
        for _arm in 'BCDE':
            r, _ = self.run_flow(p=profile())
            outputs.append((dict(r.headers), r.raw_content))
        self.assertTrue(all(o == outputs[0] for o in outputs))

    def test_legacy_profile_is_available(self):
        r, _ = self.run_flow(p=profile(version=MINIMAL))
        self.assertIn('legacy ops gateway', r.text)
        self.assertIn('X-Legacy-Gateway', r.headers)
        self.assertNotIn('X-Debug-Maintenance', r.headers)

    def test_latest_minimal_profile_is_preserved(self):
        r, _ = self.run_flow(p=profile(version=MINIMAL_V2))
        self.assertIn('legacy ops gateway (SSH)', r.text)
        self.assertLess(r.text.index('legacy ops gateway'), r.text.index('unchanged'))
        self.assertIn('X-Legacy-Gateway', r.headers)
        self.assertNotIn('X-Debug-Maintenance', r.headers)


if __name__ == '__main__':
    unittest.main()
