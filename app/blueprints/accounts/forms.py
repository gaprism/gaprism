"""Forms of the accounts blueprint. Labels are translated in the templates, not here. What a form
refuses with is translated when it refuses (see app/forms.py)."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField

from app.forms import AtMost, Entered

MAX_PASSWORD_LENGTH = 256


def _strip(value: str | None) -> str | None:
    return value.strip() if isinstance(value, str) else value


class SetPasswordForm(FlaskForm):
    """A new password, twice. The view judges the length (the service's rule) and the match."""

    password = PasswordField(
        validators=[
            Entered("Enter a new password."),
            AtMost(
                MAX_PASSWORD_LENGTH,
                "The password has more than %(max)d characters. Use a shorter one.",
            ),
        ]
    )
    confirm = PasswordField(validators=[Entered("Enter the same password again.")])
    submit = SubmitField()


class InviteForm(FlaskForm):
    """The person to invite: an address, and whether they become an administrator. The screen shows
    the first refusal as a message above the list of accounts."""

    email = StringField(
        validators=[
            Entered("Enter the e-mail address of the person to invite."),
            AtMost(
                255, "An e-mail address has at most %(max)d characters. Check what you entered."
            ),
        ],
        filters=[_strip],
    )
    admin = BooleanField()
    submit = SubmitField()
