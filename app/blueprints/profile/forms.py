"""The form of the profile page. The label is translated in the template."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField

from app.service.profile import MAX_NAME_LENGTH


class ProfileForm(FlaskForm):
    """The name; an empty one takes it away. The browser gets the limit as ``maxlength``; what is
    cleaned and refused is the service's to judge, once, so the form has no rules of its own."""

    name = StringField(render_kw={"maxlength": MAX_NAME_LENGTH})
    submit = SubmitField()
