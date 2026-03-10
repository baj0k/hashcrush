"""Forms Page to manage Tasks"""

from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, ValidationError

from hashcrush.forms_utils import normalize_text_input
from hashcrush.models import Tasks


class TasksForm(FlaskForm):
    """Class representing Tasks Forms"""

    def __init__(self, *args, current_task_id: int | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_task_id = current_task_id

    name = StringField('Name', validators=[DataRequired()], filters=[normalize_text_input])
    hc_attackmode = SelectField(
        'Attack Mode',
        choices=[('', '--SELECT--'), ('dictionary', 'dictionary'), ('maskmode', 'maskmode')],
        validators=[DataRequired()],
    )
    wl_id = SelectField('Wordlist', choices=[], validate_choice=False)
    rule_id = SelectField('Rules', choices=[], validate_choice=False)
    mask = StringField('Hashcat Mask')
    submit = SubmitField('Create') 

    def validate_name(self, name):
        """Function to validate Task name group"""

        task = Tasks.query.filter_by(name=name.data).first()
        if task and task.id != self.current_task_id:
            raise ValidationError('That task name is taken. Please choose a different one.')
