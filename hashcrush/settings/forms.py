"""Forms Page to manage Settings"""
from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange


class HashCrushSettingsForm(FlaskForm):
    """Class representing an Settings Forms"""

    max_runtime_jobs = IntegerField(
        'Maximum runtime per Job in hours. (0 = infinate)',
        validators=[DataRequired(), NumberRange(min=0, max=65535)],
    )
    max_runtime_tasks = IntegerField(
        'Maximum runtime per Task in hours. (0 = infinate)',
        validators=[DataRequired(), NumberRange(min=0, max=65535)],
    )
    submit = SubmitField('Update')

