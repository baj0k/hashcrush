"""Class file to manage loading of database"""

from datetime import UTC, datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utc_now_naive() -> datetime:
    """Return current UTC datetime without tzinfo for naive DB DateTime columns."""
    return datetime.now(UTC).replace(tzinfo=None)


class Users(db.Model, UserMixin):
    """Class object to represent Users"""

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    last_login_utc = db.Column(db.DateTime, nullable=True, default=utc_now_naive)
    jobs = db.relationship("Jobs", backref="owner", lazy=True)


class Settings(db.Model):
    """Class object to represent Settings"""

    id = db.Column(db.Integer, primary_key=True)
    retention_period = db.Column(db.Integer, nullable=False, default=0)
    enabled_job_weights = db.Column(db.Boolean, nullable=False, default=False)


class Jobs(db.Model):
    """Class object to represent Jobs"""

    __table_args__ = (
        db.UniqueConstraint("name", name="uq_jobs_name"),
        db.Index(
            "ix_jobs_status_priority_queued_at", "status", "priority", "queued_at"
        ),
        db.Index("ix_jobs_owner_id_created_at", "owner_id", "created_at"),
        db.Index("ix_jobs_domain_id_status", "domain_id", "status"),
        db.Index("ix_jobs_hashfile_id", "hashfile_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    priority = db.Column(
        db.Integer, nullable=False, default=3
    )  # 5 = highest priority. 1 = lowest priority
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)
    queued_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(
        db.String(20), nullable=False
    )  # Running, Paused, Completed, Queued, Canceled, Ready, Incomplete
    started_at = db.Column(
        db.DateTime, nullable=True
    )  # These defaults should be changed
    ended_at = db.Column(db.DateTime, nullable=True)  # These defaults should be changed
    hashfile_id = db.Column(
        db.Integer, db.ForeignKey("hashfiles.id", ondelete="RESTRICT"), nullable=True
    )
    domain_id = db.Column(
        db.Integer, db.ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False
    )
    owner_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )


class JobTasks(db.Model):
    """Class object to represent JobTasks"""

    __table_args__ = (
        db.Index("ix_job_tasks_status_priority_id", "status", "priority", "id"),
        db.Index("ix_job_tasks_job_id_status", "job_id", "status"),
        db.Index("ix_job_tasks_task_id", "task_id"),
        db.UniqueConstraint("job_id", "task_id", name="uq_job_tasks_job_id_task_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(
        db.Integer, db.ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False
    )
    task_id = db.Column(
        db.Integer, db.ForeignKey("tasks.id", ondelete="RESTRICT"), nullable=False
    )
    priority = db.Column(db.Integer, nullable=False, default=3)
    command = db.Column(db.String(1024))
    status = db.Column(
        db.String(50), nullable=False
    )  # Running, Paused, Not Started, Completed, Queued, Canceled, Importing
    started_at = db.Column(
        db.DateTime, nullable=True
    )  # These defaults should be changed
    progress = db.Column(db.String(6000))
    benchmark = db.Column(db.String(20))
    worker_pid = db.Column(db.Integer)


class Domains(db.Model):
    """Class object to represent Domains"""

    __table_args__ = (db.UniqueConstraint("name", name="uq_domains_name"),)

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), nullable=False)


class Hashfiles(db.Model):
    """Class object to represent Hashfiles"""

    __table_args__ = (
        db.Index("ix_hashfiles_uploaded_at", "uploaded_at"),
        db.Index("ix_hashfiles_domain_id_uploaded_at", "domain_id", "uploaded_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)  # can probably be reduced
    uploaded_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)
    runtime = db.Column(db.Integer, default=0)
    domain_id = db.Column(
        db.Integer, db.ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False
    )


class HashfileHashes(db.Model):
    """Class object to represent HashfileHashes"""

    __table_args__ = (
        db.UniqueConstraint(
            "hashfile_id",
            "hash_id",
            "username",
            name="uq_hashfile_hashes_hashfile_hash_username",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    hash_id = db.Column(
        db.Integer,
        db.ForeignKey("hashes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    username = db.Column(db.String(256), nullable=False, default="", index=True)
    hashfile_id = db.Column(
        db.Integer,
        db.ForeignKey("hashfiles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )


class Rules(db.Model):
    __table_args__ = (
        db.UniqueConstraint("name", name="uq_rules_name"),
        db.UniqueConstraint("path", name="uq_rules_path"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=utc_now_naive)
    path = db.Column(db.String(256), nullable=False)
    size = db.Column(db.Integer, nullable=False, default=0)
    checksum = db.Column(db.String(64), nullable=False)


class Wordlists(db.Model):
    """Class object to represent Wordlists"""

    __table_args__ = (
        db.UniqueConstraint("name", name="uq_wordlists_name"),
        db.UniqueConstraint("path", name="uq_wordlists_path"),
        db.Index("ix_wordlists_type_last_updated", "type", "last_updated"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=utc_now_naive)
    type = db.Column(db.String(7))  # Dynamic or Static
    path = db.Column(db.String(245), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    checksum = db.Column(db.String(64), nullable=False)


class Tasks(db.Model):
    """Class object to represent Tasks"""

    __table_args__ = (
        db.UniqueConstraint("name", name="uq_tasks_name"),
        db.Index("ix_tasks_wl_id", "wl_id"),
        db.Index("ix_tasks_rule_id", "rule_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    hc_attackmode = db.Column(db.String(25), nullable=False)  # dictionary, maskmode
    wl_id = db.Column(
        db.Integer, db.ForeignKey("wordlists.id", ondelete="RESTRICT"), nullable=True
    )
    rule_id = db.Column(
        db.Integer, db.ForeignKey("rules.id", ondelete="RESTRICT"), nullable=True
    )
    hc_mask = db.Column(db.String(50))


class TaskGroups(db.Model):
    """Class object to represent TaskGroups"""

    __table_args__ = (db.UniqueConstraint("name", name="uq_task_groups_name"),)

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    tasks = db.Column(db.Text, nullable=False)


class Hashes(db.Model):
    """Class object to represent Hashes"""

    __table_args__ = (
        db.UniqueConstraint(
            "hash_type", "sub_ciphertext", name="uq_hashes_hash_type_sub_ciphertext"
        ),
        db.Index("ix_hashes_cracked_hash_type", "cracked", "hash_type"),
    )

    id = db.Column(db.Integer, primary_key=True)
    sub_ciphertext = db.Column(db.String(32), nullable=False, index=True)
    # TEXT avoids row-size pressure while keeping large hash payload support.
    ciphertext = db.Column(db.Text, nullable=False)
    hash_type = db.Column(db.Integer, nullable=False, index=True)
    cracked = db.Column(db.Boolean, nullable=False)
    plaintext = db.Column(db.String(256), index=True)


class AuthThrottle(db.Model):
    """Persistent auth throttle state shared by all web worker processes."""

    key = db.Column(db.String(255), primary_key=True)
    count = db.Column(db.Integer, nullable=False, default=0)
    window_start = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.Integer, nullable=False, default=0, index=True)


class SchemaVersion(db.Model):
    """Singleton row tracking the applied in-place schema upgrade version."""

    __tablename__ = "schema_version"

    id = db.Column(db.Integer, primary_key=True, default=1)
    version = db.Column(db.Integer, nullable=False)
    app_version = db.Column(db.String(32), nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)


class AuditLog(db.Model):
    """Immutable audit trail for sensitive app actions."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        db.Index("ix_audit_logs_created_at", "created_at"),
        db.Index("ix_audit_logs_event_type_created_at", "event_type", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now_naive)
    actor_user_id = db.Column(db.Integer, nullable=True)
    actor_username = db.Column(db.String(64), nullable=False, default="<unknown>")
    actor_admin = db.Column(db.Boolean, nullable=False, default=False)
    actor_ip = db.Column(db.String(64), nullable=True)
    event_type = db.Column(db.String(64), nullable=False)
    target_type = db.Column(db.String(64), nullable=False)
    target_id = db.Column(db.String(64), nullable=True)
    summary = db.Column(db.String(255), nullable=False)
    details_json = db.Column(db.Text, nullable=False, default="{}")
