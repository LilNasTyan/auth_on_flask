from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone


db = SQLAlchemy()

# Таблица для связи пользователей и ролей
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('assigned_at', db.DateTime, default=datetime.now(timezone.utc))
)


class User(db.Model):
    # Информация о пользователе
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    role = db.Column(db.String(50), default="user")

    # Информация о пароле пользователя
    password_hash = db.Column(db.String(200), nullable=False)
    must_change_password = db.Column(db.Boolean, default=True)
    password_changed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Связь с ролями
    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))

    # Функция для установки пароля
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Функция для проверки пароля
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Проверка наличия роли
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)

    # Проверка наличия разрешения
    def has_permission(self, permission_name):
        for role in self.roles:
            if any(perm.name == permission_name for perm in role.permissions):
                return True
        return False

    # Получение всех разрешений пользователя
    def get_all_permissions(self):
        permissions = set()
        for role in self.roles:
            permissions.update([perm.name for perm in role.permissions])
        return list(permissions)

    # Получение имен ролей
    def get_role_names(self):
        return [role.name for role in self.roles]


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    permissions = db.relationship('Permission', secondary='role_permissions',
                                  backref=db.backref('roles', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'permissions': [perm.name for perm in self.permissions],
            'user_count': self.users.count()
        }


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))
    category = db.Column(db.String(50))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category
        }


role_permissions = db.Table('role_permissions', db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True), db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True))


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    action_type = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now)
    status = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text)
    ip_address = db.Column(db.String(45))

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'action_type': self.action_type,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'message': self.message,
            'ip_address': self.ip_address
        }