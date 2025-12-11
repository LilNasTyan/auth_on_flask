import re
from datetime import datetime, timezone, timedelta


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

