"""Validators that refuse in our words. The library's own say "This field is required." and "Field
cannot be longer than 255 characters."; these say what to enter. The sentence is English text with
%(name)s placeholders, looked up when the form refuses: the validators are built once, and the
language is the request's."""

from __future__ import annotations

from wtforms import Field, Form
from wtforms.validators import DataRequired, Length, StopValidation, ValidationError

from app.i18n import gettext as _


class Entered(DataRequired):
    """DataRequired that refuses with what to enter, not that "this field is required". It still
    marks the input as required. ``refusal`` is the English text, translated on use."""

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
