"""Forms to manage Wordlists."""
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, SubmitField

from hashcrush.forms_utils import normalize_text_input


class WordlistsForm(FlaskForm):
    """Form for uploading a shared static wordlist."""

    name = StringField("Name", filters=[normalize_text_input])
    upload = FileField("Upload Wordlist")
    submit = SubmitField("Upload")
