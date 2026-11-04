"""The profile page. Thin: it is for whoever is signed in, and it asks the service."""

from __future__ import annotations

from flask import flash, redirect, render_template, url_for
from flask_security import login_required
from werkzeug.wrappers import Response

from app.blueprints.assessments.access import current_user_object
from app.blueprints.profile import profile_bp
from app.blueprints.profile.forms import ProfileForm
from app.extensions import db
from app.i18n import gettext as _
from app.service import profile as profile_service
from app.service.users import UserAdminError


@profile_bp.route("/", methods=["GET", "POST"])
@login_required
def index() -> str | Response:
    """The address of the signed-in person, and the name they go by."""
    me = current_user_object()
    form = ProfileForm(data={"name": me.name or ""})
    if form.validate_on_submit():
        try:
            profile_service.change_name(db.session(), me, form.name.data)
        except UserAdminError as exc:
            db.session.rollback()
            form.name.errors.append(_(exc.message, **exc.params))
        else:
            db.session.commit()
            flash(_("Profile saved."), "info")
            return redirect(url_for("profile.index"))
    return render_template(
        "profile/index.html", form=form, max_name=profile_service.MAX_NAME_LENGTH
    )
