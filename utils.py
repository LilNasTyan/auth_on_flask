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


PASSWORD_EXPIRE_DAYS = 1

# Проверка жизни пароля
def is_password_expired(user):
    if not user.password_changed_at:
        return True  # если даты нет, считаем срок истекшим
    return datetime.now(timezone.utc) - user.password_changed_at > timedelta(days=PASSWORD_EXPIRE_DAYS)

