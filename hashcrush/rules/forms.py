"""Forms to manage Rules."""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField

from hashcrush.utils.forms import normalize_text_input


class RulesForm(FlaskForm):
    """Form for registering a mounted rule file."""

    name = StringField("Name", filters=[normalize_text_input])
    external_path = StringField(
        "Mounted Rule Path",
        filters=[normalize_text_input],
    )
    submit = SubmitField("Register Rule")
