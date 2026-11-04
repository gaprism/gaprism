"""Forms for assessments. Labels are translated in the templates, not here. What a form refuses with
is translated when it refuses: the validators are built once, the language is the request's."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import Field, Form, RadioField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, Optional, StopValidation, ValidationError

from app.i18n import gettext as _
from app.models.assessment import VISIBILITIES
from app.service.discovery.scope import EMPTY


def _strip(value: str | None) -> str | None:
    return value.strip() if isinstance(value, str) else value


class Entered(DataRequired):
    """DataRequired that refuses in our words: what to enter, not that "this field is required".
    It still marks the input as required. ``refusal`` is the English text, translated on use."""

    def __init__(self, refusal: str) -> None:
        super().__init__()
        self.refusal = refusal

    def __call__(self, form: Form, field: Field) -> None:
        if field.data and (not isinstance(field.data, str) or field.data.strip()):
            return
        field.errors[:] = []
        raise StopValidation(_(self.refusal))


class AtMost(Length):
    """Length(max=...) that refuses in our words, with %(max)d in the text. It still sets
    maxlength on the input, so a browser does not let anyone type past it."""

    def __init__(self, maximum: int, refusal: str) -> None:
        super().__init__(max=maximum)
        self.refusal = refusal

    def __call__(self, form: Form, field: Field) -> None:
        if len(field.data or "") > self.max:
            raise ValidationError(_(self.refusal, max=self.max))


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
