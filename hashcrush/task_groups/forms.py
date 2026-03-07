"""Forms Page to manage Setup"""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, ValidationError
from hashcrush.models import TaskGroups


class TaskGroupsForm(FlaskForm):
    """Class representing Task Group Forms"""

    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Create')  

    def validate_name(self, name):
        """Function to validate task group name"""

        task_group = TaskGroups.query.filter_by(name = name.data).first()
        if task_group:
            raise ValidationError('That task group name is taken. Please choose a different one.')
