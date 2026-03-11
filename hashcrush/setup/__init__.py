import json
import os

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, select

from hashcrush.models import Settings, TaskGroups, Tasks, Users

DEFAULT_PASSWORD = os.getenv("HASHCRUSH_DEFAULT_ADMIN_PASSWORD", "hashcrush")


def get_primary_admin_user(db: SQLAlchemy) -> Users | None:
    return db.session.execute(
        select(Users).filter_by(admin=True).order_by(Users.id.asc())
    ).scalars().first()


def default_tasks_need_added(db: SQLAlchemy) -> bool:
    return (db.session.scalar(select(func.count()).select_from(Tasks)) or 0) == 0


def add_default_tasks(db: SQLAlchemy):
    task_ids = []

    for length in range(1, 11):
        mask = "?a" * length
        task = Tasks(
            name=f"{mask} [{length}]",
            wl_id=None,
            rule_id=None,
            hc_attackmode="maskmode",
            hc_mask=mask,
        )
        db.session.add(task)
        db.session.flush()
        task_ids.append(task.id)

    default_group_name = "maskmode 1-10"
    if not db.session.execute(
        select(TaskGroups).filter_by(name=default_group_name)
    ).scalars().first():
        task_group = TaskGroups(
            name=default_group_name,
            tasks=json.dumps(task_ids),
        )
        db.session.add(task_group)

    db.session.commit()


def admin_user_needs_added(db: SQLAlchemy) -> bool:
    return (
        db.session.scalar(select(func.count()).select_from(Users).filter_by(admin=True))
        or 0
    ) <= 0


def add_admin_user(db: SQLAlchemy, bcrypt: Bcrypt):
    default_password_hash = bcrypt.generate_password_hash(DEFAULT_PASSWORD).decode(
        "utf-8"
    )
    user = Users(
        username="admin",
        password=default_password_hash,
        admin=True,
    )
    db.session.add(user)
    db.session.commit()


def admin_pass_needs_changed(db: SQLAlchemy, bcrypt: Bcrypt) -> bool:
    admin_user = get_primary_admin_user(db)
    if not admin_user:
        return False

    return bcrypt.check_password_hash(admin_user.password, DEFAULT_PASSWORD)


def settings_needs_added(db: SQLAlchemy) -> bool:
    settings = db.session.execute(select(Settings)).scalars().first()
    return settings is None
