"""Cross-cutting web behaviour: security headers and error pages."""

from __future__ import annotations

from flask import Flask, render_template, request
from werkzeug.exceptions import HTTPException, TooManyRequests
from werkzeug.wrappers import Response

from app.i18n import gettext as _

# No inline scripts or styles: everything is served from our own origin.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

# Generic on purpose: no internals, and 404 also covers "exists but is not yours".
_ERROR_TEXTS: dict[int, tuple[str, str]] = {
    400: ("Request not accepted", "The request could not be processed. Reload the page and retry."),
    401: ("Sign in required", "Please sign in to continue."),
    403: ("Access denied", "You do not have access to this page."),
    404: ("Not found", "This page does not exist, or you do not have access to it."),
    405: ("Method not allowed", "This action is not available here."),
    429: ("Too many attempts", "Sign-in is paused after repeated failed attempts."),
}
_FALLBACK_ERROR = ("Something went wrong", "The request could not be completed.")


def register_security_headers(app: Flask) -> None:
    """Attach security headers to every response."""

    @app.after_request
    def set_security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            # Findings about a vendor are sensitive: keep them out of every cache. Assigned, not
            # defaulted: Flask-Security emits a malformed "private=True, no-store=True" itself.
            response.headers["Cache-Control"] = "no-store"
        return response


def register_error_pages(app: Flask) -> None:
    """Render generic error pages; details go to the log, never to the browser."""

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException) -> Response | tuple[str, int, dict[str, str]]:
        code = error.code or 500
        if code < 400:  # routing redirects (e.g. missing trailing slash) are valid responses
            return error.get_response()
        title, message = _ERROR_TEXTS.get(code, _FALLBACK_ERROR)
        # Only a number of seconds is shown and sent (the limiter raises it that way).
        retry_after = error.retry_after if isinstance(error, TooManyRequests) else None
        wait = retry_after if isinstance(retry_after, int) and retry_after > 0 else None
        page = render_template(
            "errors/error.html", code=code, title=_(title), message=_(message), wait_seconds=wait
        )
        return page, code, ({"Retry-After": str(wait)} if wait else {})
