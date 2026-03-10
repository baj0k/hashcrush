"""Forms to manage shared hashfiles."""

from wtforms import SelectField, SubmitField
from wtforms.validators import DataRequired

from hashcrush.jobs.forms import JobsNewHashFileForm


class HashfilesAddForm(JobsNewHashFileForm):
    """Form for creating a shared hashfile outside the job flow."""

    domain_id = SelectField(
        "Domain",
        choices=[],
        coerce=int,
        validators=[DataRequired()],
    )
    submit = SubmitField("Create Hashfile")
