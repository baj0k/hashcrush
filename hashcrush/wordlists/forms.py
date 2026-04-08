"""Forms to manage Wordlists."""
from flask_wtf import FlaskForm
from wtforms import FileField, SelectField, StringField, SubmitField

from hashcrush.forms_utils import normalize_text_input


class WordlistsForm(FlaskForm):
    """Form for uploading or registering a shared static wordlist."""

    source_mode = SelectField(
        "Source",
        choices=[
            ("upload", "Upload File"),
            ("external", "Register Mounted File"),
        ],
        default="upload",
    )
    name = StringField("Name", filters=[normalize_text_input])
    upload = FileField("Upload Wordlist")
    external_path = StringField(
        "Mounted Wordlist Path",
        filters=[normalize_text_input],
    )
    submit = SubmitField("Save Wordlist")
