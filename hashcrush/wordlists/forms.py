"""Forms Page to manage Wordlists"""
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired


class WordlistsForm(FlaskForm):
    """Class representing Wordlist Form"""

    name = StringField('Name', validators=[DataRequired()])
    existing_file = SelectField('File from wordlists_path', choices=[('', '--SELECT FILE--')], validators=[DataRequired()])
    submit = SubmitField('Register')
