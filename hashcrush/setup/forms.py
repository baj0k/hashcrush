"""Forms to manage setup flows."""
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length

from hashcrush.forms_utils import normalize_text_input


class SetupAdminPassForm(FlaskForm):
    """Class representing an Admin Pass Forms"""

    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=50)], filters=[normalize_text_input])
    password         = PasswordField('Password',         validators=[DataRequired(), Length(min=14)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit           = SubmitField('Update')


class SetupSettingsForm(FlaskForm):
    """Class representing an Settings Forms"""

    submit = SubmitField('Save')
