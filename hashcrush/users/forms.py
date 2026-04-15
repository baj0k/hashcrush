"""Forms Page to manage Users"""
from flask_wtf import FlaskForm
from sqlalchemy import select
from wtforms import (
    BooleanField,
    PasswordField,
    StringField,
    SubmitField,
    ValidationError,
)
from wtforms.validators import DataRequired, EqualTo, Length, Optional

from hashcrush.utils.forms import normalize_text_input
from hashcrush.models import Users, db


class UsersForm(FlaskForm):
    """Class representing Users Form"""

    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=50)], filters=[normalize_text_input])
    is_admin = BooleanField('Is Admin')
    password = PasswordField('Password', validators=[DataRequired(), Length(min=14)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        """Function to validate username uniqueness."""
        user = db.session.execute(select(Users).filter_by(username=username.data)).scalars().first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    """Class representing Login Form"""

    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=50)], filters=[normalize_text_input])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ProfileForm(FlaskForm):
    """Class representing Profile Form"""

    current_password = PasswordField('Current Password', validators=[Optional()])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=14)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('new_password')])
    submit = SubmitField('Update')
