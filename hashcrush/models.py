"""Class file to manage loading of database."""

from __future__ import annotations

from datetime import UTC, datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

db = SQLAlchemy()


def utc_now_naive() -> datetime:
    """Return current UTC datetime without tzinfo for naive DB DateTime columns."""
    return datetime.now(UTC).replace(tzinfo=None)


class Users(db.Model, UserMixin):
    """Class object to represent Users"""

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(60), nullable=False)
    admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_login_utc: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
        default=utc_now_naive,
    )
    jobs: Mapped[list[Jobs]] = relationship(
        "Jobs",
        back_populates="owner",
        lazy="select",
    )


class UploadOperations(db.Model):
    """Persistent state for async upload progress polling."""

    __tablename__ = "upload_operations"
    __table_args__ = (
        db.Index(
            "ix_upload_operations_owner_user_id_updated_at",
            "owner_user_id",
            "updated_at",
        ),
        db.Index("ix_upload_operations_state_updated_at", "state", "updated_at"),
        db.Index(
            "ix_upload_operations_state_lease_created_at",
            "state",
            "lease_expires_at",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    operation_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="legacy_inline",
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    redirect_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completion_flashes_json: Mapped[str] = mapped_column(
        Text, nullable=False, default="[]"
    )
    completion_flashes_consumed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utc_now_naive
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utc_now_naive
    )


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

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    priority: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3
    )  # 5 = highest priority. 1 = lowest priority
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utc_now_naive
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utc_now_naive
    )
    queued_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # Running, Paused, Completed, Queued, Canceled, Ready, Incomplete
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )  # These defaults should be changed
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )  # These defaults should be changed
    hashfile_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("hashfiles.id", ondelete="RESTRICT"),
        nullable=True,
    )
    domain_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("domains.id", ondelete="RESTRICT"),
        nullable=False,
    )
    owner_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    owner: Mapped[Users] = relationship(
        "Users",
        back_populates="jobs",
        lazy="select",
    )
    domain: Mapped[Domains] = relationship(
        "Domains",
        back_populates="jobs",
        lazy="select",
    )
    hashfile: Mapped[Hashfiles | None] = relationship(
        "Hashfiles",
        back_populates="jobs",
        lazy="select",
    )
    job_tasks: Mapped[list[JobTasks]] = relationship(
        "JobTasks",
        back_populates="job",
        lazy="select",
    )


class JobTasks(db.Model):
    """Class object to represent JobTasks"""

    __table_args__ = (
        db.Index("ix_job_tasks_status_priority_id", "status", "priority", "id"),
        db.Index("ix_job_tasks_job_id_status", "job_id", "status"),
        db.Index("ix_job_tasks_job_id_position", "job_id", "position"),
        db.Index("ix_job_tasks_task_id", "task_id"),
        db.UniqueConstraint("job_id", "task_id", name="uq_job_tasks_job_id_task_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    task_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("tasks.id", ondelete="RESTRICT"),
        nullable=False,
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    command: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # Running, Paused, Not Started, Completed, Queued, Canceled, Importing
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )  # These defaults should be changed
    progress: Mapped[str | None] = mapped_column(String(6000), nullable=True)
    benchmark: Mapped[str | None] = mapped_column(String(20), nullable=True)
    worker_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    job: Mapped[Jobs] = relationship(
        "Jobs",
        back_populates="job_tasks",
        lazy="select",
    )
    task: Mapped[Tasks] = relationship(
        "Tasks",
        back_populates="job_tasks",
        lazy="select",
    )


class Domains(db.Model):
    """Class object to represent Domains"""

    __table_args__ = (db.UniqueConstraint("name", name="uq_domains_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(40), nullable=False)
    jobs: Mapped[list[Jobs]] = relationship(
        "Jobs",
        back_populates="domain",
        lazy="select",
    )
    hashfiles: Mapped[list[Hashfiles]] = relationship(
        "Hashfiles",
        back_populates="domain",
        lazy="select",
    )


class Hashfiles(db.Model):
    """Class object to represent Hashfiles"""

    __table_args__ = (
        db.Index("ix_hashfiles_uploaded_at", "uploaded_at"),
        db.Index("ix_hashfiles_domain_id_uploaded_at", "domain_id", "uploaded_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)  # can probably be reduced
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utc_now_naive,
    )
    runtime: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    domain_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("domains.id", ondelete="RESTRICT"),
        nullable=False,
    )
    domain: Mapped[Domains] = relationship(
        "Domains",
        back_populates="hashfiles",
        lazy="select",
    )
    jobs: Mapped[list[Jobs]] = relationship(
        "Jobs",
        back_populates="hashfile",
        lazy="select",
    )
    hashfile_hashes: Mapped[list[HashfileHashes]] = relationship(
        "HashfileHashes",
        back_populates="hashfile",
        lazy="select",
    )


class HashfileHashes(db.Model):
    """Class object to represent HashfileHashes"""

    __table_args__ = (
        db.UniqueConstraint(
            "hashfile_id",
            "hash_id",
            "username_digest",
            name="uq_hashfile_hashes_hashfile_hash_username_digest",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hash_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("hashes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    username: Mapped[str] = mapped_column(
        Text, nullable=False, default=""
    )
    username_digest: Mapped[str] = mapped_column(
        String(64), nullable=False, default="", index=True
    )
    hashfile_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("hashfiles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    hash: Mapped[Hashes] = relationship(
        "Hashes",
        back_populates="hashfile_hashes",
        lazy="select",
    )
    hashfile: Mapped[Hashfiles] = relationship(
        "Hashfiles",
        back_populates="hashfile_hashes",
        lazy="select",
    )


class Rules(db.Model):
    __table_args__ = (
        db.UniqueConstraint("name", name="uq_rules_name"),
        db.UniqueConstraint("path", name="uq_rules_path"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    last_updated: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utc_now_naive
    )
    path: Mapped[str] = mapped_column(String(256), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    tasks: Mapped[list[Tasks]] = relationship(
        "Tasks",
        back_populates="rule",
        lazy="select",
    )


class Wordlists(db.Model):
    """Class object to represent Wordlists"""

    __table_args__ = (
        db.UniqueConstraint("name", name="uq_wordlists_name"),
        db.UniqueConstraint("path", name="uq_wordlists_path"),
        db.Index("ix_wordlists_type_last_updated", "type", "last_updated"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    last_updated: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utc_now_naive
    )
    type: Mapped[str | None] = mapped_column(String(7), nullable=True)  # Dynamic or Static
    path: Mapped[str] = mapped_column(String(245), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    tasks: Mapped[list[Tasks]] = relationship(
        "Tasks",
        back_populates="wordlist",
        lazy="select",
    )


class Tasks(db.Model):
    """Class object to represent Tasks"""

    __table_args__ = (
        db.UniqueConstraint("name", name="uq_tasks_name"),
        db.Index("ix_tasks_wl_id", "wl_id"),
        db.Index("ix_tasks_rule_id", "rule_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    hc_attackmode: Mapped[str] = mapped_column(
        String(25), nullable=False
    )  # dictionary, maskmode
    wl_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("wordlists.id", ondelete="RESTRICT"),
        nullable=True,
    )
    rule_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("rules.id", ondelete="RESTRICT"),
        nullable=True,
    )
    hc_mask: Mapped[str | None] = mapped_column(String(50), nullable=True)
    wordlist: Mapped[Wordlists | None] = relationship(
        "Wordlists",
        back_populates="tasks",
        lazy="select",
    )
    rule: Mapped[Rules | None] = relationship(
        "Rules",
        back_populates="tasks",
        lazy="select",
    )
    job_tasks: Mapped[list[JobTasks]] = relationship(
        "JobTasks",
        back_populates="task",
        lazy="select",
    )


class TaskGroups(db.Model):
    """Class object to represent TaskGroups"""

    __table_args__ = (db.UniqueConstraint("name", name="uq_task_groups_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    tasks: Mapped[str] = mapped_column(Text, nullable=False)


class Hashes(db.Model):
    """Class object to represent Hashes"""

    __table_args__ = (
        db.UniqueConstraint(
            "hash_type", "sub_ciphertext", name="uq_hashes_hash_type_sub_ciphertext"
        ),
        db.Index("ix_hashes_cracked_hash_type", "cracked", "hash_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sub_ciphertext: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    hash_type: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    cracked: Mapped[bool] = mapped_column(Boolean, nullable=False)
    plaintext: Mapped[str | None] = mapped_column(Text, nullable=True)
    plaintext_digest: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    hashfile_hashes: Mapped[list[HashfileHashes]] = relationship(
        "HashfileHashes",
        back_populates="hash",
        lazy="select",
    )


class AuthThrottle(db.Model):
    """Persistent auth throttle state shared by all web worker processes."""

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_start: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, index=True
    )


class SchemaVersion(db.Model):
    """Singleton row tracking the applied in-place schema upgrade version."""

    __tablename__ = "schema_version"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    app_version: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utc_now_naive
    )


class AuditLog(db.Model):
    """Immutable audit trail for sensitive app actions."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        db.Index("ix_audit_logs_created_at", "created_at"),
        db.Index("ix_audit_logs_event_type_created_at", "event_type", "created_at"),
        db.Index(
            "ix_audit_logs_actor_username_created_at",
            "actor_username",
            "created_at",
        ),
        db.Index(
            "ix_audit_logs_target_type_created_at",
            "target_type",
            "created_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utc_now_naive
    )
    actor_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor_username: Mapped[str] = mapped_column(
        String(64), nullable=False, default="<unknown>"
    )
    actor_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    actor_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str] = mapped_column(String(255), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
