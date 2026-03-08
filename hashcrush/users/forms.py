"""Forms Page to manage Users"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, ValidationError, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Optional
from hashcrush.models import Users

class UsersForm(FlaskForm):
    """Class representing Users Form"""

    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=50)])
    is_admin = BooleanField('Is Admin')
    password = PasswordField('Password', validators=[DataRequired(), Length(min=14)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        """Function to validate username uniqueness."""
        user = Users.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    """Class representing Login Form"""

    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ProfileForm(FlaskForm):
    """Class representing Profile Form"""

    current_password = PasswordField('Current Password', validators=[Optional()])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=14)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('new_password')])
    submit = SubmitField('Update')
