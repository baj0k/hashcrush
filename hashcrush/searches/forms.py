"""Forms to manage searches."""
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired

from hashcrush.forms_utils import normalize_text_input


class SearchForm(FlaskForm):
    """Class representing search forms."""

    search_type = SelectField('Search Type', choices=[('user', 'user'), ('hash', 'hash'), ('password', 'password')], validators=[DataRequired()])
    query = StringField('', validators=[DataRequired()], filters=[normalize_text_input])
    submit = SubmitField('Search')
    export = SubmitField('Export')
    export_type = SelectField('Export Separator', choices=[('Colon', 'Colon'),('Comma', 'Comma')], default='Colon')
