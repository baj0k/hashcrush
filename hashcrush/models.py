"""Class file to manage loading of database"""
from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class Users(db.Model, UserMixin):
    """Class object to represent Users"""

    id = db.Column(db.Integer, nullable=False, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    last_login_utc = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    wordlists = db.relationship('Wordlists', backref='owner', lazy=True)
    rules = db.relationship('Rules', backref='owner', lazy=True)
    jobs = db.relationship('Jobs', backref='owner', lazy=True)
    tasks = db.relationship('Tasks', backref='owner', lazy=True)
    taskgroups = db.relationship('TaskGroups', backref='owner', lazy=True)

class Settings(db.Model):
    """Class object to represent Settings"""

    id = db.Column(db.Integer, primary_key=True)
    retention_period = db.Column(db.Integer, nullable=False, default=0)
    enabled_job_weights = db.Column(db.Boolean, nullable=False, default=False)

class Jobs(db.Model):
    """Class object to represent Jobs"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    priority = db.Column(db.Integer, nullable=False, default=3) # 5 = highest priority. 1 = lowest priority
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    queued_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), nullable=False)           # Running, Paused, Completed, Queued, Canceled, Ready, Incomplete
    started_at = db.Column(db.DateTime, nullable=True)          # These defaults should be changed
    ended_at = db.Column(db.DateTime, nullable=True)            # These defaults should be changed
    hashfile_id = db.Column(db.Integer, nullable=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class JobTasks(db.Model):
    """Class object to represent JobTasks"""

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, nullable=False)
    task_id = db.Column(db.Integer, nullable=False)
    priority = db.Column(db.Integer, nullable=False, default=3)
    command = db.Column(db.String(1024))
    status = db.Column(db.String(50), nullable=False)       # Running, Paused, Not Started, Completed, Queued, Canceled, Importing
    started_at = db.Column(db.DateTime, nullable=True)      # These defaults should be changed
    progress = db.Column(db.String(6000))
    benchmark = db.Column(db.String(20))
    worker_pid = db.Column(db.Integer)

class Domains(db.Model):
    """Class object to represent Domains"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), nullable=False)

class Hashfiles(db.Model):
    """Class object to represent Hashfiles"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)        # can probably be reduced
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    runtime = db.Column(db.Integer, default=0)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class HashfileHashes(db.Model):
    """Class object to represent HashfileHashes"""

    id = db.Column(db.Integer, primary_key=True)
    hash_id = db.Column(db.Integer, nullable=False, index=True)
    username = db.Column(db.String(256), nullable=True, default=None, index=True)
    hashfile_id = db.Column(db.Integer, nullable=False)

class Rules(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    path = db.Column(db.String(256), nullable=False)
    size = db.Column(db.Integer, nullable=False, default=0)
    checksum = db.Column(db.String(64), nullable=False)

class Wordlists(db.Model):
    """Class object to represent Wordlists"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(7))                          # Dynamic or Static
    path = db.Column(db.String(245), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    checksum = db.Column(db.String(64), nullable=False)

class Tasks(db.Model):
    """Class object to represent Tasks"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    hc_attackmode = db.Column(db.String(25), nullable=False) # dictionary, mask, bruteforce, combinator
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    wl_id = db.Column(db.Integer)
    rule_id = db.Column(db.Integer)
    hc_mask = db.Column(db.String(50))

class TaskGroups(db.Model):
    """Class object to represent TaskGroups"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tasks = db.Column(db.String(256), nullable=False)

class Hashes(db.Model):
    """Class object to represent Hashes"""

    id = db.Column(db.Integer, primary_key=True)
    sub_ciphertext = db.Column(db.String(32), nullable=False, index=True)
    # TEXT avoids MySQL row-size limits while keeping large hash payload support.
    ciphertext = db.Column(db.Text, nullable=False)
    hash_type = db.Column(db.Integer, nullable=False, index=True)
    cracked = db.Column(db.Boolean, nullable=False)
    plaintext = db.Column(db.String(256), index=True)
