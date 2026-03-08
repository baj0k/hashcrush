"""Forms Page to manage Setup"""
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms import SubmitField
from wtforms import PasswordField
from wtforms.validators import Length
from wtforms.validators import EqualTo
from wtforms.validators import DataRequired


class SetupAdminPassForm(FlaskForm):
    """Class representing an Admin Pass Forms"""

    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=50)])
    password         = PasswordField('Password',         validators=[DataRequired(), Length(min=14)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit           = SubmitField('Update')


class SetupSettingsForm(FlaskForm):
    """Class representing an Settings Forms"""

    submit = SubmitField('Save')
