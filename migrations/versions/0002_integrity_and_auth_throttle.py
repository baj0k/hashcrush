"""Add auth throttle table and integrity constraints.

Revision ID: 0002_integrity_and_auth_throttle
Revises: 0001_single_node_baseline
Create Date: 2026-03-08 14:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0002_integrity_and_auth_throttle"
down_revision = "0001_single_node_baseline"
branch_labels = None
depends_on = None


def _dedupe_for_new_constraints() -> None:
    connection = op.get_bind()

    # Normalize username NULL -> empty string before adding NOT NULL + unique tuple.
    connection.execute(sa.text("UPDATE hashfile_hashes SET username = '' WHERE username IS NULL"))

    # Remove duplicate hash links before adding uniqueness.
    connection.execute(
        sa.text(
            """
            DELETE FROM hashfile_hashes
            WHERE id IN (
                SELECT id
                FROM (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY hashfile_id, hash_id, COALESCE(username, '')
                            ORDER BY id
                        ) AS row_num
                    FROM hashfile_hashes
                ) ranked
                WHERE ranked.row_num > 1
            )
            """
        )
    )

    # Point duplicate hash references at the canonical (lowest-id) hash row.
    connection.execute(
        sa.text(
            """
            UPDATE hashfile_hashes
            SET hash_id = (
                SELECT MIN(h2.id)
                FROM hashes h1
                JOIN hashes h2
                    ON h1.hash_type = h2.hash_type
                    AND h1.sub_ciphertext = h2.sub_ciphertext
                WHERE h1.id = hashfile_hashes.hash_id
            )
            WHERE hash_id IN (
                SELECT id
                FROM (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY hash_type, sub_ciphertext
                            ORDER BY id
                        ) AS row_num
                    FROM hashes
                ) ranked
                WHERE ranked.row_num > 1
            )
            """
        )
    )

    # Hash links can collide after canonicalization; dedupe again.
    connection.execute(
        sa.text(
            """
            DELETE FROM hashfile_hashes
            WHERE id IN (
                SELECT id
                FROM (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY hashfile_id, hash_id, COALESCE(username, '')
                            ORDER BY id
                        ) AS row_num
                    FROM hashfile_hashes
                ) ranked
                WHERE ranked.row_num > 1
            )
            """
        )
    )

    # Remove duplicate hashes by (hash_type, sub_ciphertext).
    connection.execute(
        sa.text(
            """
            DELETE FROM hashes
            WHERE id IN (
                SELECT id
                FROM (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY hash_type, sub_ciphertext
                            ORDER BY id
                        ) AS row_num
                    FROM hashes
                ) ranked
                WHERE ranked.row_num > 1
            )
            """
        )
    )

    # Remove duplicate task assignments per job.
    connection.execute(
        sa.text(
            """
            DELETE FROM job_tasks
            WHERE id IN (
                SELECT id
                FROM (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY job_id, task_id
                            ORDER BY id
                        ) AS row_num
                    FROM job_tasks
                ) ranked
                WHERE ranked.row_num > 1
            )
            """
        )
    )


def upgrade():
    _dedupe_for_new_constraints()

    op.create_table(
        "auth_throttle",
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_start", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_index("ix_auth_throttle_locked_until", "auth_throttle", ["locked_until"], unique=False)

    with op.batch_alter_table("hashfile_hashes") as batch_op:
        batch_op.alter_column(
            "username",
            existing_type=sa.String(length=256),
            nullable=False,
            server_default="",
        )
        batch_op.create_unique_constraint(
            "uq_hashfile_hashes_hashfile_hash_username",
            ["hashfile_id", "hash_id", "username"],
        )

    with op.batch_alter_table("hashes") as batch_op:
        batch_op.create_unique_constraint(
            "uq_hashes_hash_type_sub_ciphertext",
            ["hash_type", "sub_ciphertext"],
        )
        batch_op.create_index(
            "ix_hashes_cracked_hash_type",
            ["cracked", "hash_type"],
            unique=False,
        )

    with op.batch_alter_table("job_tasks") as batch_op:
        batch_op.create_unique_constraint(
            "uq_job_tasks_job_id_task_id",
            ["job_id", "task_id"],
        )
        batch_op.create_index(
            "ix_job_tasks_job_id_status",
            ["job_id", "status"],
            unique=False,
        )


def downgrade():
    with op.batch_alter_table("job_tasks") as batch_op:
        batch_op.drop_index("ix_job_tasks_job_id_status")
        batch_op.drop_constraint("uq_job_tasks_job_id_task_id", type_="unique")

    with op.batch_alter_table("hashes") as batch_op:
        batch_op.drop_index("ix_hashes_cracked_hash_type")
        batch_op.drop_constraint("uq_hashes_hash_type_sub_ciphertext", type_="unique")

    with op.batch_alter_table("hashfile_hashes") as batch_op:
        batch_op.drop_constraint("uq_hashfile_hashes_hashfile_hash_username", type_="unique")
        batch_op.alter_column(
            "username",
            existing_type=sa.String(length=256),
            nullable=True,
            server_default=None,
        )

    op.drop_index("ix_auth_throttle_locked_until", table_name="auth_throttle")
    op.drop_table("auth_throttle")
