"""Unit and integration tests for isolated browser supervisor and anti-SSRF egress (NET-02)."""

from __future__ import annotations

import socket
import threading
import urllib.parse
from collections.abc import Generator

import pytest

pytest.importorskip("playwright.sync_api", reason="needs the 'screenshots' extra")

from playwright.sync_api import Route, sync_playwright

from runner.browser import _is_safe_host, capture_screenshot


class EphemeralHTTPServer:
    """Ephemeral in-process HTTP server for testing browser capture and route interception."""

    def __init__(self, routes: dict[str, tuple[int, str, str]]) -> None:
        """routes map: path -> (status_code, content_type, body)."""
        self.routes = routes
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(5)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        self._sock.settimeout(0.5)
        while not self._stop_event.is_set():
            try:
                client_sock, _ = self._sock.accept()
                threading.Thread(
                    target=self._handle_client, args=(client_sock,), daemon=True
                ).start()
            except TimeoutError:
                continue
            except Exception:
                break

    def _handle_client(self, client_sock: socket.socket) -> None:
        try:
            client_sock.settimeout(2.0)
            req_data = client_sock.recv(4096).decode("utf-8", errors="ignore")
            if not req_data:
                client_sock.close()
                return

            first_line = req_data.split("\r\n")[0]
            parts = first_line.split(" ")
            path = parts[1] if len(parts) > 1 else "/"

            if path in self.routes:
                status, ct, body = self.routes[path]
            else:
                status, ct, body = (404, "text/plain", "Not Found")

            body_bytes = body.encode("utf-8")
            response = (
                f"HTTP/1.1 {status} OK\r\n"
                f"Content-Type: {ct}\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + body_bytes

            client_sock.sendall(response)
            client_sock.close()
        except Exception:
            try:
                client_sock.close()
            except Exception:
                pass

    def close(self) -> None:
        self._stop_event.set()
        try:
            self._sock.close()
        except Exception:
            pass
        self._thread.join(timeout=1.0)


@pytest.fixture
def http_server() -> Generator[EphemeralHTTPServer, None, None]:
    html_doc = (
        "<!DOCTYPE html><html><head><title>Due Diligence Test</title></head>"
        "<body><h1>Target SaaS App</h1><p>Public Content</p></body></html>"
    )
    routes = {
        "/": (200, "text/html; charset=utf-8", html_doc),
        "/api/health": (200, "application/json", '{"status": "ok", "version": "1.0"}'),
        "/doc.pdf": (200, "application/pdf", "%PDF-1.4 binary mock stream"),
        "/with_ssrf_subresources": (
            200,
            "text/html",
            "<!DOCTYPE html><html><body><h1>SSRF Probing Page</h1>"
            '<img src="http://169.254.169.254/latest/meta-data/">'
            '<img src="http://127.0.0.1:8080/internal">'
            "</body></html>",
        ),
    }
    server = EphemeralHTTPServer(routes)
    yield server
    server.close()


class TestBrowserSandbox:
    def test_invalid_url_rejection(self) -> None:
        res = capture_screenshot("ftp://invalid.com/file")
        assert res.status == "failed"
        assert res.reason_code == "invalid_url"

        res_noscheme = capture_screenshot("example.com")
        assert res_noscheme.status == "failed"

    def test_net_02_blocked_destination_private_ips(self) -> None:
        # Loopback URL rejected
        res = capture_screenshot("http://127.0.0.1:8080/")
        assert res.status == "failed"
        assert res.reason_code == "blocked_destination"

        # Cloud metadata rejected
        res_meta = capture_screenshot("http://169.254.169.254/latest/meta-data/")
        assert res_meta.status == "failed"
        assert res_meta.reason_code == "blocked_destination"

        # Pinned private IP rejected
        res_pinned = capture_screenshot("http://example.com/", pinned_ip="10.0.0.1")
        assert res_pinned.status == "failed"
        assert res_pinned.reason_code == "blocked_destination"

    def test_missing_isolation_blocks_capture(self, http_server: EphemeralHTTPServer) -> None:
        url = f"http://example.com:{http_server.port}/api/health"
        res = capture_screenshot(url, pinned_ip="93.184.216.34")
        assert res.status == "failed"
        assert res.reason_code == "runner_isolation_unavailable"
        assert res.screenshot_bytes is None

    def test_ssrf_subresources_interception(self) -> None:
        blocked_count = 0
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 900})

            def handle_route(route: Route) -> None:
                nonlocal blocked_count
                req_url = route.request.url
                parsed = urllib.parse.urlparse(req_url)
                if parsed.scheme in ("http", "https"):
                    host = parsed.hostname or ""
                    if not _is_safe_host(host):
                        blocked_count += 1
                        route.abort("blockedbyclient")
                        return
                route.continue_()

            page.route("**/*", handle_route)
            page.set_content(
                "<html><body><h1>SSRF Test</h1>"
                '<img src="http://169.254.169.254/latest/meta-data/credentials">'
                '<img src="http://127.0.0.1:8080/internal.png">'
                "</body></html>"
            )
            browser.close()

        assert blocked_count == 2

    def test_html_screenshot_capture_success(self) -> None:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.set_content(
                "<html><head><title>SaaS Portal</title></head><body><h1>Welcome</h1></body></html>"
            )
            shot = page.screenshot(type="png")
            browser.close()

            assert len(shot) > 1000
            assert shot[:8] == b"\x89PNG\r\n\x1a\n"
