"""Forms Page to manage Rules"""
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired

from hashcrush.forms_utils import normalize_text_input


class RulesForm(FlaskForm):
    """Class representing rule registration forms."""

    name = StringField('Name', validators=[DataRequired()], filters=[normalize_text_input])
    existing_file = SelectField('File from rules_path', choices=[('', '--SELECT FILE--')], validators=[DataRequired()])
    submit = SubmitField('Register')
