"""Forms to manage Rules."""
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, SubmitField

from hashcrush.utils.forms import normalize_text_input


class RulesForm(FlaskForm):
    """Form for uploading a shared rule file."""

    name = StringField("Name", filters=[normalize_text_input])
    upload = FileField("Upload Rule")
    submit = SubmitField("Upload")
