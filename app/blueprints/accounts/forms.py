"""Forms of the accounts blueprint. Labels are translated in the templates, not here."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length

MAX_PASSWORD_LENGTH = 256


def _strip(value: str | None) -> str | None:
    return value.strip() if isinstance(value, str) else value


class SetPasswordForm(FlaskForm):
    """A new password, twice. The view judges the length (the service's rule) and the match."""

    password = PasswordField(validators=[DataRequired(), Length(max=MAX_PASSWORD_LENGTH)])
    confirm = PasswordField(validators=[DataRequired()])
    submit = SubmitField()


class InviteForm(FlaskForm):
    """The person to invite: an address, and whether they become an administrator."""

    email = StringField(validators=[DataRequired(), Length(max=255)], filters=[_strip])
    admin = BooleanField()
    submit = SubmitField()
