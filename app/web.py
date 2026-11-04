"""Cross-cutting web behaviour: security headers and error pages."""

from __future__ import annotations

import logging

from flask import Flask, render_template, request
from werkzeug.exceptions import HTTPException, TooManyRequests
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers import Response

from app.i18n import gettext as _

log = logging.getLogger(__name__)

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
    413: (
        "Request too large",
        "The request was larger than this installation accepts. "
        "If you were sending a picture, choose a smaller one.",
    ),
    429: ("Too many attempts", "Sign-in is paused after repeated failed attempts."),
}
_FALLBACK_ERROR = ("Something went wrong", "The request could not be completed.")


def register_proxy_fix(app: Flask) -> None:
    """Believe the forwarding headers of the reverse proxies in front of the app, and no one else's.

    ``TRUSTED_PROXY_COUNT`` is how many proxies append to ``X-Forwarded-For``: that many entries
    from the right are taken, so a client that sends the header itself cannot pick its address
    (its own entries stand to the left of the proxies'). The address matters because the sign-in
    rate limit counts failures per address; without this every client behind a proxy would share
    the proxy's address and five failures from anybody would block everybody. With 0 (the default)
    the headers are ignored, which is right when clients connect directly.
    """
    hops = int(app.config["TRUSTED_PROXY_COUNT"])
    if hops:
        # Only the client address and the scheme; the Host header is never taken from a proxy.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops)  # type: ignore[method-assign]
        return

    warned = False

    @app.before_request
    def warn_about_untrusted_proxy() -> None:
        # A forwarding header with nobody trusted is a proxy nobody told the app about: sign-ins
        # of all clients would be counted as one address. Say so once, never log the header.
        nonlocal warned
        if not warned and "X-Forwarded-For" in request.headers:
            warned = True
            log.warning(
                "A request carries X-Forwarded-For but TRUSTED_PROXY_COUNT is 0, so the "
                "forwarded client address is ignored and the sign-in limit sees the proxy's "
                "address for every client. Behind one reverse proxy set TRUSTED_PROXY_COUNT=1."
            )


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
        # A person's picture is the one thing besides our own files that a browser may keep: it is
        # not about a vendor, its URL names the picture (a new one has a new URL), and the view
        # sets its own Cache-Control, private. An error for it is kept out of every cache as well.
        delivered = response.status_code in (200, 304)  # the picture, or "you have it already"
        picture_served = request.endpoint == "profile.picture" and delivered
        if request.endpoint != "static" and not picture_served:
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
