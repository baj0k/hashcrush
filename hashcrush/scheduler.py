"""Scheduler support functions."""
from logging import Logger

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler


scheduler = APScheduler()


def _data_retention_cleanup_inner(db :SQLAlchemy, logger :Logger):
    """Data retention culling is obsolete; preserve all DB data indefinitely."""

    from hashcrush.models import Settings

    setting = Settings.query.first()
    if not setting:
        logger.warning('DataRetentionCleanup skipped: no settings row found.')
        return

    if setting.retention_period != 0:
        setting.retention_period = 0
        db.session.commit()
        logger.info('DataRetentionCleanup set nonzero retention_period to 0 (infinite retention).')

    logger.info('DataRetentionCleanup skipped: retention policy is obsolete and data is retained indefinitely.')


def data_retention_cleanup(app :Flask):
    """Run the retention cleanup task."""
    with app.app_context():
        try:
            app.logger.info('DataRetentionCleanup scheduled job started.')

            logger = app.logger
            from hashcrush.models import db
            _data_retention_cleanup_inner(db, logger)

        except Exception:
            app.logger.exception('DataRetentionCleanup scheduled job failed.')

        else:
            app.logger.info('DataRetentionCleanup scheduled job completed successfully.')
