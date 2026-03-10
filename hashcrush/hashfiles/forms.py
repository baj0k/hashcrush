"""Forms to manage hashfiles."""
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, SubmitField
from wtforms.validators import DataRequired

from hashcrush.forms_utils import normalize_text_input


class HashfilesForm(FlaskForm):
    """Class representing hashfile upload forms."""

    name = StringField('Hashfile Name', validators=[DataRequired()], filters=[normalize_text_input])
    hashfile = FileField('Upload Hashfile')
    submit = SubmitField('Upload')
