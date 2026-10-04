"""Screenshot result contract; capture is blocked until isolated execution is available."""

from __future__ import annotations

import datetime
import ipaddress
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

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
    """Validate the destination and report the missing isolated-runner boundary.

    No browser is launched and no screenshot evidence is fabricated.
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

    # In-process route callbacks do not prevent DNS rebinding, WebRTC or browser
    # background traffic. Never launch an untrusted page in this process.
    return ScreenshotResult(
        status="failed",
        reason_code="runner_isolation_unavailable",
        url=url,
        error_message="Screenshot collection requires an isolated runner with enforced egress.",
    )
