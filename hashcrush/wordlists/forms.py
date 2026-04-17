"""Forms to manage Wordlists."""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField

from hashcrush.utils.forms import normalize_text_input


class WordlistsForm(FlaskForm):
    """Form for registering a mounted static wordlist."""

    name = StringField("Name", filters=[normalize_text_input])
    external_path = StringField(
        "Mounted Wordlist Path",
        filters=[normalize_text_input],
    )
    submit = SubmitField("Register Wordlist")
