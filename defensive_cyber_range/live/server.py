"""Local Live Folder API.

A deliberately small, dependency-free HTTP service for the Live Folder console.
It binds to the loopback interface, accepts only local browser origins, allows
an explicit set of roots, and is read-only unless ``--allow-write`` is passed.

Run::

    python -m live.server --root /path/to/project --allow-write

The service is intentionally not a general-purpose web server. It is the local
half of the platform; the static dashboard can be served from ``dashboard/`` or
from the Vite dev server during development.
"""

from __future__ import annotations

import argparse
import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import sys
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .service import LiveService, ServiceError

LOG = logging.getLogger("cyberrange.live")

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
ORIGIN_RE = re.compile(r"^http://(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$", re.I)
HOST_RE = re.compile(r"^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$", re.I)
MAX_BODY = 64 * 1024

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".txt": "text/plain; charset=utf-8",
    ".map": "application/json; charset=utf-8",
}


def _origin_allowed(origin: str | None) -> bool:
    # No Origin is a non-browser client (curl); those still need loopback access
    # and cannot be triggered by a remote web page.
    return origin is None or bool(ORIGIN_RE.match(origin))


def _host_allowed(host: str | None) -> bool:
    return bool(host and HOST_RE.match(host))


class LiveHandler(BaseHTTPRequestHandler):
    server_version = "CyberRangeLive/1.0"
    protocol_version = "HTTP/1.1"

    @property
    def service(self) -> LiveService:
        return self.server.service  # type: ignore[attr-defined]

    @property
    def static_dir(self) -> Path | None:
        return self.server.static_dir  # type: ignore[attr-defined]

    # ------------------------------------------------------------- responses

    def _cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin and _origin_allowed(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Max-Age", "600")

    def _json(self, payload: Any, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self._cors_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _error(self, status: int, code: str, message: str) -> None:
        self._json({"error": {"code": code, "message": message}}, status)

    def _guard(self) -> bool:
        if not _host_allowed(self.headers.get("Host")):
            self._error(403, "bad_host", "This service only accepts loopback requests.")
            return False
        if not _origin_allowed(self.headers.get("Origin")):
            self._error(
                403,
                "foreign_origin",
                "Cross-origin requests are limited to local dashboard origins.",
            )
            return False
        return True

    # ------------------------------------------------------------------ HTTP

    def do_OPTIONS(self) -> None:  # noqa: N802
        if not self._guard():
            return
        if not _origin_allowed(self.headers.get("Origin")):
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        if not self._guard():
            return
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/healthz":
            self._json(
                {
                    "status": "ok",
                    "service": "cyberrange-live",
                    "mode": "live",
                    "allow_write": self.service.allow_write,
                }
            )
            return

        if path == "/api/config":
            self._json(self.service.config())
            return

        if path == "/api/scan":
            root = parse_qs(parsed.query).get("root", [None])[0]
            try:
                result = self.service.scan(root)
            except ServiceError as exc:
                self._error(exc.status, exc.code, str(exc))
                return
            except (ValueError, OSError) as exc:
                self._error(400, "scan_failed", str(exc))
                return
            self._json(result.to_dict())
            return

        if path.startswith("/api/"):
            self._error(404, "not_found", "Unknown API endpoint.")
            return

        self._serve_static(path)

    def do_POST(self) -> None:  # noqa: N802
        if not self._guard():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        if path not in {"/api/preview", "/api/apply", "/api/remediate"}:
            self._error(404, "not_found", "Unknown API endpoint.")
            return

        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if content_type.lower() != "application/json":
            self._error(
                415,
                "unsupported_media_type",
                "Requests must use Content-Type: application/json.",
            )
            return

        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = -1
        if length <= 0 or length > MAX_BODY:
            self._error(413, "bad_body", "Request body is missing or too large.")
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(400, "bad_json", "Request body must be valid JSON.")
            return
        if not isinstance(body, dict):
            self._error(400, "bad_json", "Request body must be a JSON object.")
            return

        root = body.get("root")
        if root is not None and not isinstance(root, str):
            self._error(400, "bad_root", "root must be a string.")
            return

        try:
            if path == "/api/preview":
                finding_id = body.get("finding_id")
                if not isinstance(finding_id, str) or not finding_id:
                    self._error(400, "bad_finding", "finding_id is required.")
                    return
                self._json(self.service.preview(root, finding_id))
                return

            if path == "/api/apply":
                finding_id = body.get("finding_id")
                if not isinstance(finding_id, str) or not finding_id:
                    self._error(400, "bad_finding", "finding_id is required.")
                    return
                expected = body.get("expected_sha256")
                if expected is not None and not isinstance(expected, str):
                    self._error(400, "bad_hash", "expected_sha256 must be a string.")
                    return
                self._json(self.service.apply(root, finding_id, expected))
                return

            max_passes = body.get("max_passes", 8)
            max_patches = body.get("max_patches", 30)
            if not isinstance(max_passes, int) or not isinstance(max_patches, int):
                self._error(400, "bad_limit", "Limits must be integers.")
                return
            self._json(
                self.service.remediate(
                    root,
                    max_passes=max(1, min(max_passes, 20)),
                    max_patches=max(1, min(max_patches, 100)),
                )
            )
            return
        except ServiceError as exc:
            self._error(exc.status, exc.code, str(exc))
            return
        except (ValueError, OSError) as exc:
            self._error(400, "operation_failed", str(exc))
            return
        except Exception:  # pragma: no cover - defensive, keep the server alive
            LOG.exception("Unhandled request failure for %s", path)
            self._error(500, "internal_error", "The local service hit an internal error.")
            return

    # ---------------------------------------------------------------- static

    def _serve_static(self, path: str) -> None:
        static = self.static_dir
        if static is None or not static.is_dir():
            self._json(
                {
                    "service": "cyberrange-live",
                    "message": (
                        "Live API is running. Serve the dashboard with Vite "
                        "(npm run dev) or pass --static-dir pointing at a built "
                        "dashboard."
                    ),
                    "api": "/api/config",
                }
            )
            return

        requested = unquote(path.lstrip("/")) or "index.html"
        candidate = (static / requested).resolve()
        if not candidate.is_relative_to(static):
            self._error(404, "not_found", "Not found.")
            return
        if not candidate.is_file():
            # SPA fallback for dashboard routes, but never for API paths.
            candidate = (static / "index.html").resolve()
            if not candidate.is_file():
                self._error(404, "not_found", "Dashboard build not found.")
                return

        try:
            data = candidate.read_bytes()
        except OSError:
            self._error(500, "read_failed", "Could not read dashboard asset.")
            return

        content_type = MIME_TYPES.get(candidate.suffix.lower(), "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header(
            "Cache-Control",
            "no-cache" if candidate.suffix == ".html" else "public, max-age=31536000, immutable",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.info("%s - %s", self.address_string(), fmt % args)


class LiveHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        service: LiveService,
        static_dir: Path | None,
    ) -> None:
        super().__init__(address, LiveHandler)
        self.service = service
        self.static_dir = static_dir


def _default_static_dir() -> Path | None:
    here = Path(__file__).resolve().parent
    for candidate in (here.parent / "dashboard", here.parent.parent / "dist"):
        if (candidate / "index.html").is_file():
            return candidate
    return None


def _is_loopback_host(host: str) -> bool:
    return host in LOOPBACK_HOSTS or host.startswith("127.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m live.server",
        description="Local Live Folder scanner and remediation API for Citadel.",
    )
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="PATH",
        help="Folder the service may read. Repeat for multiple roots.",
    )
    parser.add_argument(
        "--allow-write",
        action="store_true",
        help="Enable patching. Without this flag the service is strictly read-only.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Loopback bind address.")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on.")
    parser.add_argument(
        "--static-dir",
        default=None,
        help="Optional directory containing a built dashboard (index.html).",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not args.root:
        parser.error("At least one --root folder is required.")
    if not _is_loopback_host(args.host):
        parser.error(
            "Refusing to bind a non-loopback address. Live Folder Mode is local-only."
        )

    roots: list[Path] = []
    for raw in args.root:
        root = Path(raw).expanduser()
        if not root.exists() or not root.is_dir():
            parser.error(f"--root is not a directory: {raw}")
        roots.append(root.resolve())

    static_dir = Path(args.static_dir).expanduser().resolve() if args.static_dir else _default_static_dir()
    if static_dir is not None and not (static_dir / "index.html").is_file():
        parser.error(f"--static-dir has no index.html: {static_dir}")

    service = LiveService(roots, allow_write=args.allow_write)
    try:
        httpd = LiveHTTPServer((args.host, args.port), service, static_dir)
    except OSError as exc:
        LOG.error("Could not bind %s:%s: %s", args.host, args.port, exc)
        return 1

    mode = "READ/WRITE" if args.allow_write else "READ-ONLY"
    print("Citadel Live Folder service")
    print(f"  mode:     {mode}")
    print(f"  roots:    {', '.join(str(root) for root in roots)}")
    print(f"  api:      http://{args.host}:{args.port}/api/config")
    if static_dir:
        print(f"  dashboard: http://{args.host}:{args.port}/")
    else:
        print("  dashboard: not bundled; run `npm run dev` and open /live")
    print("  stop:     Ctrl+C")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Live Folder service.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
