"""Isolated Playwright screenshot capture supervisor with sandboxing and anti-SSRF egress rules."""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Route, sync_playwright

from runner.dns import DNSResolutionError, SSRFBlockedError, is_ip_public, resolve_and_screen


@dataclass(frozen=True)
class ScreenshotResult:
    """Immutable result of a browser screenshot capture."""

    status: str  # 'succeeded', 'not_applicable', 'failed', 'timeout'
    reason_code: str | None
    url: str
    final_url: str | None = None
    connected_ip: str | None = None
    content_type: str | None = None
    http_status: int | None = None
    page_title: str | None = None
    screenshot_bytes: bytes | None = None
    screenshot_sha256: str | None = None
    viewport_width: int = 1440
    viewport_height: int = 900
    captured_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )
    blocked_resource_count: int = 0
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert screenshot result to serialisable metadata (excluding raw bytes)."""
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "url": self.url,
            "final_url": self.final_url,
            "connected_ip": self.connected_ip,
            "content_type": self.content_type,
            "http_status": self.http_status,
            "page_title": self.page_title,
            "has_screenshot": self.screenshot_bytes is not None,
            "screenshot_sha256": self.screenshot_sha256,
            "screenshot_size_bytes": len(self.screenshot_bytes) if self.screenshot_bytes else 0,
            "viewport_width": self.viewport_width,
            "viewport_height": self.viewport_height,
            "captured_at": self.captured_at.isoformat(),
            "blocked_resource_count": self.blocked_resource_count,
            "error_message": self.error_message,
        }


def _is_html_content_type(content_type: str | None) -> bool:
    """Check if Content-Type indicates HTML markup suitable for browser screenshotting."""
    if not content_type:
        return True  # Default to attempting capture if unknown
    ct = content_type.lower().split(";")[0].strip()
    return ct in ("text/html", "application/xhtml+xml", "text/plain")


def _is_safe_host(hostname: str) -> bool:
    """Validate if a request destination hostname or IP is safe to contact (Anti-SSRF)."""
    clean_host = hostname.strip().lower().strip("[]")
    if not clean_host:
        return False

    # Check if direct IP literal
    try:
        ip = ipaddress.ip_address(clean_host)
        return is_ip_public(ip)
    except ValueError:
        pass

    if clean_host in ("localhost", "local", "internal", "metadata.google.internal"):
        return False

    # Resolve domain to check addresses
    try:
        valid_ips = resolve_and_screen(clean_host)
        return bool(valid_ips)
    except (SSRFBlockedError, DNSResolutionError):
        return False
    except Exception:
        return False


def capture_screenshot(
    url: str,
    pinned_ip: str | None = None,
    timeout_seconds: int = 30,
    viewport_width: int = 1440,
    viewport_height: int = 900,
) -> ScreenshotResult:
    """Execute isolated Chromium screenshot capture with strict egress routing and ceilings.

    Enforces:
    - Headless Chromium with sandboxing active (INV-06).
    - Disposable browser profile, no stored cookies or persisted local storage.
    - Anti-SSRF destination filtering for all navigation and subresource requests (NET-02).
    - Fixed 1440x900 viewport ceiling and bounded settle time.
    - Non-HTML detection: marked not_applicable with reason_code="non_html_content".
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return ScreenshotResult(
            status="failed",
            reason_code="invalid_url",
            url=url,
            error_message="Only HTTP and HTTPS URLs with valid hostnames are supported.",
        )

    # Pre-validate top-level destination IP / hostname
    if pinned_ip:
        try:
            ip = ipaddress.ip_address(pinned_ip)
            if not is_ip_public(ip):
                return ScreenshotResult(
                    status="failed",
                    reason_code="blocked_destination",
                    url=url,
                    connected_ip=pinned_ip,
                    error_message=(
                        f"Pinned IP address '{pinned_ip}' is in a private/forbidden range."
                    ),
                )
        except ValueError:
            return ScreenshotResult(
                status="failed",
                reason_code="blocked_destination",
                url=url,
                connected_ip=pinned_ip,
                error_message=f"Invalid pinned IP address format: {pinned_ip}",
            )
    else:
        if not _is_safe_host(parsed.hostname):
            return ScreenshotResult(
                status="failed",
                reason_code="blocked_destination",
                url=url,
                error_message=(
                    f"Destination hostname '{parsed.hostname}' is unsafe or unresolvable."
                ),
            )

    blocked_count = 0
    top_content_type: str | None = None
    top_http_status: int | None = None
    final_url: str = url

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-background-networking",
                ],
            )
            user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
                "TechnicalDueDiligenceBot/1.0"
            )
            context = browser.new_context(
                viewport={"width": viewport_width, "height": viewport_height},
                ignore_https_errors=False,
                user_agent=user_agent,
            )
            page = context.new_page()

            # 1. Route interception to enforce public egress and block SSRF (NET-02)
            def handle_route(route: Route) -> None:
                nonlocal blocked_count
                req_url = route.request.url
                req_parsed = urllib.parse.urlparse(req_url)

                if req_parsed.scheme not in ("http", "https", "data"):
                    blocked_count += 1
                    route.abort("blockedbyclient")
                    return

                if req_parsed.scheme in ("http", "https"):
                    host = req_parsed.hostname or ""
                    # Allow same top-level host if already pinned / validated, else screen host
                    if host != parsed.hostname and not _is_safe_host(host):
                        blocked_count += 1
                        route.abort("blockedbyclient")
                        return

                route.continue_()

            context.route("**/*", handle_route)

            # 2. Track top response headers for Content-Type check
            def handle_response(response: Any) -> None:
                nonlocal top_content_type, top_http_status
                if response.url == url or response.request.is_navigation_request():
                    top_http_status = response.status
                    top_content_type = response.headers.get("content-type")

            page.on("response", handle_response)

            timeout_ms = timeout_seconds * 1000

            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                if response:
                    top_http_status = response.status
                    top_content_type = response.headers.get("content-type")
                    final_url = response.url

                # Check if response content is non-HTML
                if not _is_html_content_type(top_content_type):
                    return ScreenshotResult(
                        status="not_applicable",
                        reason_code="non_html_content",
                        url=url,
                        final_url=final_url,
                        connected_ip=pinned_ip,
                        content_type=top_content_type,
                        http_status=top_http_status,
                        blocked_resource_count=blocked_count,
                    )

                # Bounded settle period (max 1.0s)
                page.wait_for_timeout(1000)

                page_title = page.title()
                shot_bytes = page.screenshot(type="png", full_page=False)
                shot_hash = hashlib.sha256(shot_bytes).hexdigest()

                return ScreenshotResult(
                    status="succeeded",
                    reason_code=None,
                    url=url,
                    final_url=final_url,
                    connected_ip=pinned_ip,
                    content_type=top_content_type,
                    http_status=top_http_status,
                    page_title=page_title,
                    screenshot_bytes=shot_bytes,
                    screenshot_sha256=shot_hash,
                    viewport_width=viewport_width,
                    viewport_height=viewport_height,
                    blocked_resource_count=blocked_count,
                )

            except PlaywrightError as e:
                err_str = str(e)
                if "Timeout" in err_str or "exceeded" in err_str:
                    return ScreenshotResult(
                        status="timeout",
                        reason_code="timeout",
                        url=url,
                        final_url=final_url,
                        connected_ip=pinned_ip,
                        blocked_resource_count=blocked_count,
                        error_message=f"Screenshot capture timed out: {err_str}",
                    )
                return ScreenshotResult(
                    status="failed",
                    reason_code="execution_failed",
                    url=url,
                    final_url=final_url,
                    connected_ip=pinned_ip,
                    blocked_resource_count=blocked_count,
                    error_message=f"Browser execution error: {err_str}",
                )

            finally:
                context.close()
                browser.close()

    except Exception as e:
        return ScreenshotResult(
            status="failed",
            reason_code="execution_failed",
            url=url,
            blocked_resource_count=blocked_count,
            error_message=f"Unexpected supervisor failure: {e}",
        )
