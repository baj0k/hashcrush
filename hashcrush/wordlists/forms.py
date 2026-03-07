"""Forms Page to manage Wordlists"""
from flask_wtf import FlaskForm
from wtforms import StringField, FileField, SubmitField
from wtforms.validators import DataRequired, Optional


class WordlistsForm(FlaskForm):
    """Class representing Wordlist Form"""

    name = StringField('Name', validators=[DataRequired()])
    wordlist = FileField('Upload Wordlist')
    existing_path = StringField('Use Existing File (absolute or relative to wordlists_path)', validators=[Optional()])
    submit = SubmitField('upload')
