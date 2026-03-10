"""Forms to manage domains."""

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError

from hashcrush.forms_utils import normalize_text_input
from hashcrush.models import Domains


class DomainsForm(FlaskForm):
    """Form for creating a shared domain."""

    name = StringField(
        "Name",
        validators=[DataRequired(), Length(min=1, max=40)],
        filters=[normalize_text_input],
    )
    submit = SubmitField("Add Domain")

    def validate_name(self, name):
        """Require globally unique domain names."""

        if Domains.query.filter_by(name=name.data).first():
            raise ValidationError(
                "That domain name is taken. Please choose a different one."
            )
