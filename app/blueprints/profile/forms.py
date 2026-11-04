"""The forms of the profile page. The labels are translated in the template."""

from __future__ import annotations

from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, SubmitField

from app.forms import Chosen
from app.service.images import PICTURE_TYPE
from app.service.profile import MAX_NAME_LENGTH

# The formats the service opens. A browser narrows its file dialog to them; what comes is judged
# by the service from the bytes, not by this list or by the name of the file.
ACCEPTED_TYPES = ("image/jpeg", "image/png", PICTURE_TYPE)


class ProfileForm(FlaskForm):
    """The name; an empty one takes it away. The browser gets the limit as ``maxlength``; what is
    cleaned and refused is the service's to judge, once, so the form has no rules of its own."""

    name = StringField(render_kw={"maxlength": MAX_NAME_LENGTH})
    submit = SubmitField()


class PictureForm(FlaskForm):
    """The file to make the picture of. All that is asked here is that one was chosen."""

    picture = FileField(
        validators=[Chosen("Choose a picture to upload.")],
        render_kw={"accept": ",".join(ACCEPTED_TYPES)},
    )
    submit = SubmitField()
