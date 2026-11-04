"""Forms for assessments. Labels are translated in the templates, not here. What a form refuses with
is translated when it refuses (see app/forms.py)."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import Field, Form, RadioField, StringField, SubmitField
from wtforms.validators import Optional, ValidationError

from app.forms import AtMost, Entered
from app.i18n import gettext as _
from app.models.assessment import VISIBILITIES
from app.service.discovery.scope import EMPTY


def _strip(value: str | None) -> str | None:
    return value.strip() if isinstance(value, str) else value


def _who_can_see(form: Form, field: Field) -> None:
    """The library's "Not a valid choice." says nothing; a page opened before the name ``team`` was
    retired can still send it."""
    if field.data not in VISIBILITIES:
        raise ValidationError(_("Choose who can see the assessment."))


class NewAssessmentForm(FlaskForm):
    """Domain to review, an optional label and who may see the assessment."""

    domain = StringField(
        validators=[
            Entered(EMPTY),
            AtMost(253, "A domain name has at most %(max)d characters. Check what you entered."),
        ],
        filters=[_strip],
    )
    label = StringField(
        validators=[
            Optional(),
            AtMost(255, "The label has more than %(max)d characters. Shorten it."),
        ],
        filters=[_strip],
    )
    visibility = RadioField(
        choices=[(value, value) for value in VISIBILITIES],
        default="private",
        validate_choice=False,
        validators=[_who_can_see],
    )
    submit = SubmitField()
