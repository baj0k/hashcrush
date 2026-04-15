"""Forms to manage jobs."""

from flask_wtf import FlaskForm
from sqlalchemy import select
from wtforms import FileField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, ValidationError

from hashcrush.utils.forms import normalize_text_input
from hashcrush.hashfiles.hash_types import (
    HASHFILE_HASH_TYPE_CHOICES,
    KERBEROS_HASH_TYPE_CHOICES,
    NETNTLM_HASH_TYPE_CHOICES,
    PWDUMP_HASH_TYPE_CHOICES,
    SHADOW_HASH_TYPE_CHOICES,
)
from hashcrush.models import Jobs, db


class JobsForm(FlaskForm):
    """Class representing job forms."""

    name = StringField(
        "Job Name", validators=[DataRequired()], filters=[normalize_text_input]
    )
    priority = SelectField(
        "Job Priority",
        choices=[
            ("5", "5 - highest"),
            ("4", "4 - higher"),
            ("3", "3 - normal"),
            ("2", "2 - lower"),
            ("1", "1 - lowest"),
        ],
        default=3,
        validators=[DataRequired()],
    )
    submit = SubmitField("Next")

    def validate_name(self, name):
        job = db.session.execute(select(Jobs).filter_by(name=name.data)).scalars().first()
        current_job_id = getattr(self, "current_job_id", None)
        if job and job.id != current_job_id:
            raise ValidationError(
                "That job name is taken. Please choose a different one."
            )


class JobsNewHashFileForm(FlaskForm):
    """Class representing an Jobs New Hashfile Form"""

    _OPTIONAL_HASH_SELECTOR_FIELDS = (
        "hash_type",
        "shadow_hash_type",
        "pwdump_hash_type",
        "netntlm_hash_type",
        "kerberos_hash_type",
    )

    name = StringField(
        "Hashfile Name", filters=[normalize_text_input]
    )  # While required we may dynamically create this based on file upload
    domain_name = StringField(
        "Fallback category (domain) for no-domain entries",
        default="None",
        validators=[DataRequired()],
        filters=[normalize_text_input],
    )
    file_type = SelectField(
        "Hash File Format",
        choices=[
            ("", "--SELECT--"),
            ("pwdump", "Windows pwdump"),
            ("NetNTLM", "NetNTLMv1, NetNTLMv1+ESS or NetNTLMv2"),
            ("kerberos", "Kerberos"),
            ("shadow", "Linux / Unix Shadow File"),
            ("user_hash", "$user:$hash"),
            ("hash_only", "$hash"),
        ],
        validators=[DataRequired()],
    )

    hash_type = SelectField(
        "Hash Type",
        choices=HASHFILE_HASH_TYPE_CHOICES,
    )

    shadow_hash_type = SelectField(
        "Hash Type",
        choices=SHADOW_HASH_TYPE_CHOICES,
    )

    pwdump_hash_type = SelectField(
        "Hash Type",
        choices=PWDUMP_HASH_TYPE_CHOICES,
    )

    netntlm_hash_type = SelectField(
        "Hash Type",
        choices=NETNTLM_HASH_TYPE_CHOICES,
    )

    kerberos_hash_type = SelectField(
        "Hash Type",
        choices=KERBEROS_HASH_TYPE_CHOICES,
    )

    hashfilehashes = TextAreaField("Hashes")
    hashfile = FileField("Upload Hashfile")
    submit = SubmitField("Next")

    def _normalize_optional_hash_selectors(self) -> None:
        for field_name in self._OPTIONAL_HASH_SELECTOR_FIELDS:
            field = getattr(self, field_name)
            if field.raw_data in (None, []):
                field.raw_data = [""]
                field.data = ""

    def validate(self, extra_validators=None):
        self._normalize_optional_hash_selectors()
        return super().validate(extra_validators=extra_validators)


class JobSummaryForm(FlaskForm):
    """Class representing an Jobs Summary"""

    submit = SubmitField("Complete")
