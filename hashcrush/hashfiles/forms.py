"""Forms to manage shared hashfiles."""

from wtforms import SelectField, StringField, SubmitField
from wtforms.validators import DataRequired

from hashcrush.forms_utils import normalize_text_input
from hashcrush.jobs.forms import JobsNewHashFileForm


class HashfilesAddForm(JobsNewHashFileForm):
    """Form for creating a shared hashfile outside the job flow."""

    domain_id = SelectField(
        "Domain",
        choices=[],
        coerce=str,
        validators=[DataRequired()],
    )
    domain_name = StringField("New Domain", filters=[normalize_text_input])
    submit = SubmitField("Create Hashfile")
