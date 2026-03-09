import os

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

from hashcrush.models import Settings
from hashcrush.models import TaskGroups
from hashcrush.models import Tasks
from hashcrush.models import Users


DEFAULT_PASSWORD = os.getenv('HASHCRUSH_DEFAULT_ADMIN_PASSWORD', 'hashcrush')


def default_tasks_need_added(db: SQLAlchemy) -> bool:
    return db.session.query(Tasks).count() == 0


def _default_seed_owner_id(db: SQLAlchemy) -> int:
    admin_row = db.session.query(Users.id).filter_by(admin=True).order_by(Users.id.asc()).first()
    if admin_row:
        owner_id, *_ = admin_row
        return int(owner_id)

    user_row = db.session.query(Users.id).order_by(Users.id.asc()).first()
    if user_row:
        owner_id, *_ = user_row
        return int(owner_id)

    raise RuntimeError('Cannot seed default tasks without at least one user.')


def add_default_tasks(db: SQLAlchemy):
    owner_id = _default_seed_owner_id(db)
    task_ids = []

    for length in range(1, 11):
        mask = '?a' * length
        task = Tasks(
            name=f'{mask} [{length}]',
            owner_id=owner_id,
            wl_id=None,
            rule_id=None,
            hc_attackmode='maskmode',
            hc_mask=mask,
        )
        db.session.add(task)
        db.session.flush()
        task_ids.append(task.id)

    default_group_name = 'maskmode 1-10'
    if not db.session.query(TaskGroups).filter_by(name=default_group_name).first():
        task_group = TaskGroups(
            name=default_group_name,
            owner_id=owner_id,
            tasks=str(task_ids),
        )
        db.session.add(task_group)

    db.session.commit()


def admin_user_needs_added(db: SQLAlchemy) -> bool:
    return db.session.query(Users).filter_by(admin=True).count() <= 0


def add_admin_user(db: SQLAlchemy, bcrypt: Bcrypt):
    default_password_hash = bcrypt.generate_password_hash(DEFAULT_PASSWORD).decode('utf-8')
    user = Users(
        username='admin',
        password=default_password_hash,
        admin=True,
    )
    db.session.add(user)
    db.session.commit()


def admin_pass_needs_changed(db: SQLAlchemy, bcrypt: Bcrypt) -> bool:
    row = db.session.query(Users.password).filter_by(id=1).first()
    if not row:
        return False

    current_password_hash, *_ = row
    return bcrypt.check_password_hash(current_password_hash, DEFAULT_PASSWORD)


def settings_needs_added(db: SQLAlchemy) -> bool:
    settings = db.session.query(Settings).first()
    return settings is None
