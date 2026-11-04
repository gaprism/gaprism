"""The page where somebody sets a password with a one-time link. Public by design: the link is
the credential, so the page says as little as it can and a dead link is always the same page."""

from __future__ import annotations

from flask import flash, redirect, render_template
from flask_security import url_for_security
from werkzeug.wrappers import Response

from app.blueprints.accounts import invitation_bp
from app.blueprints.accounts.forms import SetPasswordForm
from app.extensions import db
from app.i18n import gettext as _
from app.service import invitations as invitation_service
from app.service.auth.rate_limit import record_address_failure, reject_blocked_address
from app.service.users import MIN_PASSWORD_LENGTH, UserAdminError


def _dead_link() -> tuple[str, int]:
    """The one answer for every link that does not work; it counts against the address."""
    record_address_failure()
    page = render_template(
        "errors/error.html",
        code=404,
        title=_("This link does not work"),
        message=_(
            "It may have been used, withdrawn or expired. Ask the person who sent it for a new one."
        ),
        wait_seconds=None,
    )
    return page, 404


@invitation_bp.route("/<token>", methods=["GET", "POST"])
def accept(token: str) -> str | Response | tuple[str, int]:
    """Show the form for a new password, and set it. Opening the page changes nothing."""
    reject_blocked_address()
    session = db.session()
    if not invitation_service.looks_like_token(token):
        return _dead_link()
    try:
        link = invitation_service.open_link(session, token)
    except invitation_service.InvalidLinkError:
        return _dead_link()
    shown = {
        "email": link.user.email,
        "purpose": link.purpose,
        "reset_authenticator": link.reset_authenticator,
        "min_length": MIN_PASSWORD_LENGTH,
    }

    form = SetPasswordForm()
    if form.validate_on_submit():
        if form.password.data != form.confirm.data:
            form.confirm.errors.append(
                _("The two passwords are not the same. Enter the same password twice.")
            )
        else:
            try:
                invitation_service.accept_link(session, token, form.password.data)
            except invitation_service.InvalidLinkError:  # used or withdrawn a moment ago
                session.rollback()
                return _dead_link()
            except UserAdminError as exc:  # the password is refused; the link stays as it was
                session.rollback()
                form.password.errors.append(_(exc.message, **exc.params))
            else:
                session.commit()
                flash(_("Password set. Sign in to finish setting up."), "info")
                return redirect(url_for_security("login"))
    return render_template("accounts/accept.html", form=form, **shown)
