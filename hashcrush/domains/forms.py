"""Forms to manage domains."""

from flask_wtf import FlaskForm
from sqlalchemy import select
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError

from hashcrush.utils.forms import normalize_text_input
from hashcrush.models import Domains, db


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

        if db.session.execute(select(Domains).filter_by(name=name.data)).scalars().first():
            raise ValidationError(
                "That domain name is taken. Please choose a different one."
            )
