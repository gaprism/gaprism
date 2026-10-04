"""Forms for assessments. Labels are translated in the templates, not here."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import RadioField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, Optional

from app.models.assessment import VISIBILITIES


def _strip(value: str | None) -> str | None:
    return value.strip() if isinstance(value, str) else value


class NewAssessmentForm(FlaskForm):
    """Domain to review, an optional label and who may see the assessment."""

    domain = StringField(validators=[DataRequired(), Length(max=253)], filters=[_strip])
    label = StringField(validators=[Optional(), Length(max=255)], filters=[_strip])
    visibility = RadioField(choices=[(value, value) for value in VISIBILITIES], default="private")
    submit = SubmitField()
