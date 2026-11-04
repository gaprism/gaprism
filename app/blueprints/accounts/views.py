"""The account screen, for administrators. Thin: check the role, ask the service, render.

Every handler starts with ``_require_admin``: anybody else gets a 404, because there is nothing
here to confirm to them. The screen only hides the buttons that would end an administrator's own
access; the rules (the last administrator stays) are the service's, on the server.
"""

from __future__ import annotations

import uuid

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_security import login_required
from werkzeug.wrappers import Response

from app.blueprints.accounts import accounts_bp
from app.blueprints.accounts.forms import InviteForm
from app.blueprints.assessments.access import current_user_object
from app.extensions import db
from app.i18n import gettext as _
from app.models.auth import User
from app.service import invitations as invitation_service
from app.service import users as user_service
from app.service.users import AccountExistsError, UserAdminError


def _require_admin() -> User:
    me = current_user_object()
    if not user_service.holds_admin_role(me):
        abort(404)
    return me


def _account_or_404(user_id: uuid.UUID) -> User:
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    return user


def _hours() -> int:
    return int(current_app.config["INVITATION_HOURS"])


def _refused(exc: UserAdminError) -> Response:
    db.session.rollback()
    flash(_(exc.message, **exc.params), "warning")
    return redirect(url_for("accounts.index"))


def _show_link(user: User, link: invitation_service.IssuedLink, *, forgets: bool) -> str:
    """The page that shows a new link. It is rendered by the request that made the link, not
    redirected to: the link exists nowhere else, so it cannot be shown again."""
    address = request.host_url.rstrip("/") + invitation_service.link_path(link.token)
    return render_template(
        "accounts/link.html",
        email=user.email,
        address=address,
        expires_at=link.expires_at,
        purpose=link.purpose,
        forgets_authenticator=forgets,
    )


@accounts_bp.get("/")
@login_required
def index() -> str:
    """Every account with its state, and the form to invite somebody."""
    me = _require_admin()
    return render_template(
        "accounts/index.html",
        rows=user_service.list_users(db.session()),
        me_id=me.id,
        form=InviteForm(),
    )


@accounts_bp.post("/invite")
@login_required
def invite() -> str | Response:
    """Make an account for somebody who has none and show the link where they set a password."""
    _require_admin()
    form = InviteForm()
    if not form.validate_on_submit():
        first = next(iter(form.email.errors), None)
        flash(first or _("Enter the e-mail address of the person to invite."), "warning")
        return redirect(url_for("accounts.index"))
    try:
        user, link = invitation_service.invite_user(
            db.session(), form.email.data, admin=bool(form.admin.data), hours=_hours()
        )
    except AccountExistsError:  # the list below has the account: say what to do on this screen
        db.session.rollback()
        flash(
            _(
                "An account for this e-mail address exists already. "
                "Use its row in the list below to send it a new link."
            ),
            "warning",
        )
        return redirect(url_for("accounts.index"))
    except UserAdminError as exc:
        return _refused(exc)
    db.session.commit()
    return _show_link(user, link, forgets=False)


@accounts_bp.post("/<uuid:user_id>/link")
@login_required
def make_link(user_id: uuid.UUID) -> str | Response:
    """A new invitation link (account not accepted yet) or a reset link; it replaces the old one."""
    _require_admin()
    target = _account_or_404(user_id)
    authenticator = request.form.get("authenticator") == "1"
    try:
        user, link = invitation_service.new_link(
            db.session(), target.email, authenticator=authenticator, hours=_hours()
        )
    except UserAdminError as exc:
        return _refused(exc)
    db.session.commit()
    forgets = authenticator and link.purpose == invitation_service.RESET
    return _show_link(user, link, forgets=forgets)


@accounts_bp.post("/<uuid:user_id>/withdraw")
@login_required
def withdraw(user_id: uuid.UUID) -> Response:
    """Withdraw the link of an account that works at the moment."""
    _require_admin()
    target = _account_or_404(user_id)
    count = invitation_service.revoke_links(db.session(), target.email)
    db.session.commit()
    flash(
        _("Withdrew the link of %(email)s.", email=target.email)
        if count
        else _("%(email)s has no working link.", email=target.email),
        "info",
    )
    return redirect(url_for("accounts.index"))


@accounts_bp.post("/<uuid:user_id>/active")
@login_required
def set_active(user_id: uuid.UUID) -> Response:
    """Switch an account off (its sessions end with the next request) or on again."""
    _require_admin()
    target = _account_or_404(user_id)
    wanted = request.form.get("active") == "1"
    try:
        changed = user_service.set_active(db.session(), target.email, wanted)
    except UserAdminError as exc:
        return _refused(exc)
    db.session.commit()
    email = target.email
    if not changed:
        message = (
            _("%(email)s is switched on already.", email=email)
            if wanted
            else _("%(email)s is switched off already.", email=email)
        )
    elif wanted:
        message = _("%(email)s is switched on again.", email=email)
    else:
        message = _(
            "%(email)s is switched off. Their sessions end with their next request.", email=email
        )
    flash(message, "info")
    return redirect(url_for("accounts.index"))


@accounts_bp.post("/<uuid:user_id>/admin")
@login_required
def set_admin(user_id: uuid.UUID) -> Response:
    """Give or take the administrator role (never from the last active administrator)."""
    _require_admin()
    target = _account_or_404(user_id)
    wanted = request.form.get("admin") == "1"
    try:
        changed = user_service.set_admin(db.session(), target.email, wanted)
    except UserAdminError as exc:
        return _refused(exc)
    db.session.commit()
    email = target.email
    if wanted:
        message = (
            _("%(email)s is an administrator.", email=email)
            if changed
            else _("%(email)s is one already.", email=email)
        )
    else:
        message = (
            _("%(email)s is not an administrator any more.", email=email)
            if changed
            else _("%(email)s is not an administrator.", email=email)
        )
    flash(message, "info")
    return redirect(url_for("accounts.index"))


@accounts_bp.post("/<uuid:user_id>/sign-out")
@login_required
def sign_out(user_id: uuid.UUID) -> Response:
    """End every session of an account."""
    _require_admin()
    target = _account_or_404(user_id)
    user_service.sign_out_everywhere(db.session(), target.email)
    db.session.commit()
    flash(_("%(email)s is signed out everywhere.", email=target.email), "info")
    return redirect(url_for("accounts.index"))
