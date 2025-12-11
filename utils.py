import re
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import session, redirect, flash
from models import User


# Проверка надёжности пароля
def is_password_strong(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Za-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*]", password):
        return False
    return True


PASSWORD_EXPIRE_DAYS = 30


# Проверка жизни пароля
def is_password_expired(user):
    if not user.password_changed_at:
        return True

    if user.password_changed_at.tzinfo is None:
        password_changed_aware = user.password_changed_at.replace(tzinfo=timezone.utc)
    else:
        password_changed_aware = user.password_changed_at

    return datetime.now(timezone.utc) - password_changed_aware > timedelta(days=PASSWORD_EXPIRE_DAYS)


# Проверка разрешения
def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect('/login')

            user = User.query.get(session['user_id'])
            if not user:
                session.pop('user_id', None)
                return redirect('/login')

            if user.has_role('admin'):
                return f(*args, **kwargs)

            # Проверка разрешения
            if not user.has_permission(permission_name):
                from logging_system import audit_logger
                audit_logger.log_action(
                    action_type="access_denied",
                    status="failed",
                    message=f"Попытка доступа к {permission_name} без разрешения",
                    username=user.username
                )
                flash("У вас недостаточно прав для выполнения этого действия")
                return redirect('/')

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Проверка роли
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect('/login')

            user = User.query.get(session['user_id'])
            if not user:
                session.pop('user_id', None)
                return redirect('/login')

            if not user.has_role(role_name):
                from logging_system import audit_logger
                audit_logger.log_action(
                    action_type="access_denied",
                    status="failed",
                    message=f"Попытка доступа к функции, требующей роли {role_name}",
                    username=user.username
                )
                flash(f"Требуется роль {role_name}")
                return redirect('/')

            return f(*args, **kwargs)

        return decorated_function

    return decorator