import json

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, select

from hashcrush.models import TaskGroups, Tasks, Users


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
