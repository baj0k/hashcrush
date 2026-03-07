"""Forms Page to manage Rules"""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField
from wtforms.validators import DataRequired, Optional


class RulesForm(FlaskForm):
    """Class representing an Rules Forms"""

    name = StringField('Name', validators=[DataRequired()])
    rules = FileField('Upload Rules')
    existing_path = StringField('Use Existing File (absolute or relative to rules_path)', validators=[Optional()])
    submit = SubmitField('upload')
