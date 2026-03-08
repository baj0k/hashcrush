"""Forms Page to manage Rules"""
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired


class RulesForm(FlaskForm):
    """Class representing an Rules Forms"""

    name = StringField('Name', validators=[DataRequired()])
    existing_file = SelectField('File from rules_path', choices=[('', '--SELECT FILE--')], validators=[DataRequired()])
    submit = SubmitField('Register')
