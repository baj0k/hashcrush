"""Authorization helpers for route-level access control."""

from functools import wraps

from flask import flash, redirect, url_for
from flask_login import current_user


def admin_required_redirect(endpoint: str, message: str = "Permission Denied"):
    """Require an authenticated admin and redirect non-admin users."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            if not getattr(current_user, "admin", False):
                flash(message, "danger")
                return redirect(url_for(endpoint))
            return view_func(*args, **kwargs)

        return wrapped_view

    return decorator
