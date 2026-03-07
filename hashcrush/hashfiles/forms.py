"""Forms Page to manage Hashfiles"""
from flask_wtf import FlaskForm
from wtforms import StringField, FileField, SubmitField
from wtforms.validators import DataRequired

class HashfilesForm(FlaskForm):
    """Class representing hashfile upload forms."""

    name = StringField('Hashfile Name', validators=[DataRequired()])
    hashfile = FileField('Upload Hashfile')
    submit = SubmitField('Upload')
