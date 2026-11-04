"""The profile page. Thin: it is for whoever is signed in, and it asks the service."""

from __future__ import annotations

import uuid

from flask import Response, abort, flash, redirect, render_template, request, url_for
from flask_security import login_required
from werkzeug.wrappers import Response as WerkzeugResponse

from app.blueprints.assessments.access import current_user_object
from app.blueprints.profile import profile_bp
from app.blueprints.profile.forms import PictureForm, ProfileForm
from app.extensions import db
from app.i18n import gettext as _
from app.service import images
from app.service import profile as profile_service
from app.service.users import UserAdminError

_MEGABYTE = 1024 * 1024
_A_YEAR = 365 * 24 * 60 * 60


def _page(form: ProfileForm, picture_form: PictureForm) -> str:
    return render_template(
        "profile/index.html",
        form=form,
        picture_form=picture_form,
        max_name=profile_service.MAX_NAME_LENGTH,
        max_picture=images.MAX_PICTURE_BYTES // _MEGABYTE,
    )


@profile_bp.route("/", methods=["GET", "POST"])
@login_required
def index() -> str | WerkzeugResponse:
    """The address of the signed-in person, the name they go by, and their picture."""
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
    return _page(form, PictureForm(formdata=None))


@profile_bp.post("/picture")
@login_required
def upload_picture() -> str | WerkzeugResponse:
    """Make the chosen file the picture. A file that cannot be used is refused under the field."""
    me = current_user_object()
    picture_form = PictureForm()
    if picture_form.validate_on_submit():
        upload = picture_form.picture.data.read(images.MAX_PICTURE_BYTES + 1)
        try:
            profile_service.change_picture(db.session(), me, upload)
        except UserAdminError as exc:
            db.session.rollback()
            picture_form.picture.errors.append(_(exc.message, **exc.params))
        else:
            db.session.commit()
            flash(_("Picture saved."), "info")
            return redirect(url_for("profile.index"))
    return _page(ProfileForm(formdata=None, data={"name": me.name or ""}), picture_form)


@profile_bp.post("/picture/remove")
@login_required
def remove_picture() -> WerkzeugResponse:
    """Delete the picture of the signed-in person."""
    if profile_service.remove_picture(db.session(), current_user_object()):
        db.session.commit()
        flash(_("Picture removed."), "info")
    else:
        flash(_("There is no picture to remove."), "info")
    return redirect(url_for("profile.index"))


@profile_bp.get("/picture/<uuid:user_id>")
@login_required
def picture(user_id: uuid.UUID) -> WerkzeugResponse:
    """A picture, for anybody who is signed in. Its URL carries its version (``?v=``): with the
    right one a browser may keep it for a year, without it the browser asks again each time."""
    stored = profile_service.picture_of(db.session(), user_id)
    if stored is None:
        abort(404)
    version = profile_service.picture_version(stored.content)
    response = Response(stored.content, mimetype=images.PICTURE_TYPE)
    response.set_etag(version)
    response.headers["Content-Disposition"] = "inline"
    named = request.args.get("v") == version
    response.headers["Cache-Control"] = (
        f"private, max-age={_A_YEAR}, immutable" if named else "private, no-cache"
    )
    return response.make_conditional(request)
