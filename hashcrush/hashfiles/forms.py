"""Forms to manage shared hashfiles."""

from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

from hashcrush.forms_utils import normalize_text_input
from hashcrush.jobs.forms import JobsNewHashFileForm


class HashfilesAddForm(JobsNewHashFileForm):
    """Form for creating a shared hashfile outside the job flow."""

    domain_name = StringField(
        "Fallback category (domain) for no-domain entries",
        default="None",
        validators=[DataRequired()],
        filters=[normalize_text_input],
    )
    submit = SubmitField("Create Hashfile")
