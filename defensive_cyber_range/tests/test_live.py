"""Tests for Live Folder scanning, safe remediation and the local API."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from live.server import LiveHTTPServer, _host_allowed, _origin_allowed
from live.service import LiveService, ServiceError

FIXTURE = '''\
import ssl

import requests
import yaml

API_KEY = "sk_live_4f9a2c8b7d1e6f3a"
DEBUG = True


def find_user(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchone()


def load_document(payload):
    return yaml.load(payload)


def fetch(url):
    return requests.get(url, verify=False)
'''


class LiveServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "app.py").write_text(FIXTURE, encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _readonly(self) -> LiveService:
        return LiveService([self.root], allow_write=False)

    def _writable(self) -> LiveService:
        return LiveService([self.root], allow_write=True)

    def test_scan_finds_expected_rules_without_leaking_secret(self) -> None:
        scan = self._readonly().scan(self.root)
        rules = {finding.rule_id for finding in scan.findings}
        self.assertIn("PY-SQLI-001", rules)
        self.assertIn("PY-YAML-001", rules)
        self.assertIn("PY-SECRET-001", rules)
        self.assertIn("PY-TLS-001", rules)

        secret = next(f for f in scan.findings if f.rule_id == "PY-SECRET-001")
        self.assertNotIn("sk_live_4f9a2c8b7d1e6f3a", secret.snippet)
        self.assertIn("<redacted", secret.snippet)

        sql = next(f for f in scan.findings if f.rule_id == "PY-SQLI-001")
        self.assertTrue(sql.safe_auto)
        self.assertEqual(sql.severity, "CRITICAL")

    def test_read_only_service_refuses_apply(self) -> None:
        scan = self._readonly().scan(self.root)
        sql = next(f for f in scan.findings if f.rule_id == "PY-SQLI-001")
        with self.assertRaises(ServiceError) as ctx:
            self._readonly().apply(self.root, sql.id)
        self.assertEqual(ctx.exception.status, 403)
        self.assertIn("SELECT", (self.root / "app.py").read_text(encoding="utf-8"))

    def test_apply_patches_verifies_and_creates_backup(self) -> None:
        service = self._writable()
        scan = service.scan(self.root)
        sql = next(f for f in scan.findings if f.rule_id == "PY-SQLI-001")

        result = service.apply(self.root, sql.id, sql.file_sha256)
        self.assertEqual(result["status"], "applied")
        self.assertTrue(result["verified"])
        self.assertTrue((self.root / result["backup_path"]).is_file())

        content = (self.root / "app.py").read_text(encoding="utf-8")
        self.assertIn('cursor.execute("SELECT * FROM users WHERE name = ?", (name,))', content)
        compile(content, "app.py", "exec")

        rescan = service.scan(self.root)
        self.assertNotIn(sql.id, {finding.id for finding in rescan.findings})
        self.assertFalse(any(f.file_path == "app.py" and f.rule_id == "PY-SQLI-001" for f in rescan.findings))

    def test_stale_scan_is_rejected(self) -> None:
        service = self._writable()
        scan = service.scan(self.root)
        sql = next(f for f in scan.findings if f.rule_id == "PY-SQLI-001")

        # A newline changes the checksum but not the vulnerability.
        with (self.root / "app.py").open("a", encoding="utf-8") as handle:
            handle.write("\n# touched\n")

        with self.assertRaises(ServiceError) as ctx:
            service.apply(self.root, sql.id, sql.file_sha256)
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.code, "stale_file")

    def test_remediate_loop_fixes_safe_findings(self) -> None:
        service = self._writable()
        result = service.remediate(self.root, max_passes=6, max_patches=10)
        self.assertGreaterEqual(result["applied"], 2)
        self.assertGreaterEqual(result["initial_findings"], result["remaining"])
        self.assertTrue(all(item["status"] in {"applied", "reverted", "error"} for item in result["log"]))

        content = (self.root / "app.py").read_text(encoding="utf-8")
        self.assertIn("yaml.safe_load(payload)", content)
        self.assertIn("verify=True", content)
        self.assertIn('"SELECT * FROM users WHERE name = ?"', content)
        compile(content, "app.py", "exec")

        final = service.scan(self.root)
        self.assertEqual(sum(1 for f in final.findings if f.safe_auto), 0)

    def test_unapproved_root_is_rejected(self) -> None:
        service = self._readonly()
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(PermissionError):
                service.scan(other)

    def test_origin_and_host_guards(self) -> None:
        self.assertTrue(_origin_allowed("http://localhost:5173"))
        self.assertTrue(_origin_allowed("http://127.0.0.1:8765"))
        self.assertTrue(_origin_allowed(None))
        self.assertFalse(_origin_allowed("https://evil.example"))
        self.assertTrue(_host_allowed("127.0.0.1:8765"))
        self.assertTrue(_host_allowed("localhost:8765"))
        self.assertFalse(_host_allowed("evil.example"))


class LiveApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "app.py").write_text(FIXTURE, encoding="utf-8")
        self.service = LiveService([self.root], allow_write=False)
        self.httpd = LiveHTTPServer(("127.0.0.1", 0), self.service, None)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.httpd.server_address[:2]
        self.base = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        self._tmp.cleanup()

    def test_health_is_unauthenticated_but_local(self) -> None:
        with urlopen(self.base + "/healthz", timeout=5) as response:
            payload = json.loads(response.read())
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["mode"], "live")

    def test_scan_from_local_origin(self) -> None:
        request = Request(
            self.base + "/api/scan?root=" + quote(str(self.root)),
            headers={"Origin": "http://localhost:5173"},
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read())
        self.assertGreater(payload["summary"]["total"], 0)
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "http://localhost:5173")

    def test_foreign_origin_is_blocked(self) -> None:
        request = Request(
            self.base + "/api/scan?root=" + quote(str(self.root)),
            headers={"Origin": "https://evil.example"},
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(request, timeout=5)
        self.assertEqual(ctx.exception.code, 403)
        ctx.exception.close()

    def test_read_only_apply_returns_403(self) -> None:
        scan_request = Request(
            self.base + "/api/scan?root=" + quote(str(self.root)),
            headers={"Origin": "http://localhost:5173"},
        )
        with urlopen(scan_request, timeout=5) as response:
            scan = json.loads(response.read())
        finding = next(f for f in scan["findings"] if f["rule_id"] == "PY-SQLI-001")
        payload = json.dumps(
            {"root": str(self.root), "finding_id": finding["id"]}
        ).encode()
        request = Request(
            self.base + "/api/apply",
            data=payload,
            method="POST",
            headers={
                "Origin": "http://localhost:5173",
                "Content-Type": "application/json",
            },
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(request, timeout=5)
        self.assertEqual(ctx.exception.code, 403)
        error = json.loads(ctx.exception.read())
        self.assertEqual(error["error"]["code"], "read_only")
        ctx.exception.close()


if __name__ == "__main__":
    unittest.main()
