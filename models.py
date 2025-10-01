from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone


db = SQLAlchemy()


class User(db.Model):
    # Информация о пользователе
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    role = db.Column(db.String(50), default="user")

    # Информация о пароле пользователя
    password_hash = db.Column(db.String(200), nullable=False)
    must_change_password = db.Column(db.Boolean, default=True)
    password_changed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Функция для установки пароля
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Функция для проверки пароля
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
