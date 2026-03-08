"""Single-node baseline schema.

Revision ID: 0001_single_node_baseline
Revises:
Create Date: 2026-02-28 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0001_single_node_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=50), nullable=False),
        sa.Column("password", sa.String(length=60), nullable=False),
        sa.Column("admin", sa.Boolean(), nullable=False),
        sa.Column("last_login_utc", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )

    op.create_table(
        "settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("retention_period", sa.Integer(), nullable=False),
        sa.Column("enabled_job_weights", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "domains",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=40), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "hashfiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(), nullable=False),
        sa.Column("runtime", sa.Integer(), nullable=True),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"]),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("queued_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("hashfile_id", sa.Integer(), nullable=True),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"]),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("last_updated", sa.DateTime(), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(length=256), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "wordlists",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("last_updated", sa.DateTime(), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=7), nullable=True),
        sa.Column("path", sa.String(length=245), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "tasks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("hc_attackmode", sa.String(length=25), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("wl_id", sa.Integer(), nullable=True),
        sa.Column("rule_id", sa.Integer(), nullable=True),
        sa.Column("hc_mask", sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "task_groups",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("tasks", sa.String(length=256), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "hashes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("sub_ciphertext", sa.String(length=32), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("hash_type", sa.Integer(), nullable=False),
        sa.Column("cracked", sa.Boolean(), nullable=False),
        sa.Column("plaintext", sa.String(length=256), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_hashes_sub_ciphertext"), "hashes", ["sub_ciphertext"], unique=False)
    op.create_index(op.f("ix_hashes_hash_type"), "hashes", ["hash_type"], unique=False)
    op.create_index(op.f("ix_hashes_plaintext"), "hashes", ["plaintext"], unique=False)

    op.create_table(
        "hashfile_hashes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("hash_id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=256), nullable=True),
        sa.Column("hashfile_id", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_hashfile_hashes_hash_id"), "hashfile_hashes", ["hash_id"], unique=False)
    op.create_index(op.f("ix_hashfile_hashes_username"), "hashfile_hashes", ["username"], unique=False)

    op.create_table(
        "job_tasks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("command", sa.String(length=1024), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("progress", sa.String(length=6000), nullable=True),
        sa.Column("benchmark", sa.String(length=20), nullable=True),
        sa.Column("worker_pid", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("job_tasks")

    op.drop_index(op.f("ix_hashfile_hashes_username"), table_name="hashfile_hashes")
    op.drop_index(op.f("ix_hashfile_hashes_hash_id"), table_name="hashfile_hashes")
    op.drop_table("hashfile_hashes")

    op.drop_index(op.f("ix_hashes_plaintext"), table_name="hashes")
    op.drop_index(op.f("ix_hashes_hash_type"), table_name="hashes")
    op.drop_index(op.f("ix_hashes_sub_ciphertext"), table_name="hashes")
    op.drop_table("hashes")

    op.drop_table("task_groups")
    op.drop_table("tasks")
    op.drop_table("wordlists")
    op.drop_table("rules")
    op.drop_table("jobs")
    op.drop_table("hashfiles")
    op.drop_table("domains")
    op.drop_table("settings")
    op.drop_table("users")
