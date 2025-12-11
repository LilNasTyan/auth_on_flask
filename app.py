from flask import Flask, render_template
from dotenv import load_dotenv
from models import db, User, Role, Permission
from datetime import datetime, timezone
from logging_system import audit_logger
import os
from routes.auth import auth_bp
from routes.logs import audit_bp
from routes.obfuscation import obfuscation_bp
from routes.roles import roles_bp


load_dotenv()

# Инициализация приложения
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# БД
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
db.init_app(app)

# Инициализация модуля логирования
audit_logger.init_app(app)

# Регистрируем бп
app.register_blueprint(auth_bp)
app.register_blueprint(audit_bp)
app.register_blueprint(obfuscation_bp)
app.register_blueprint(roles_bp)


def initialize_roles_and_permissions():
    # Создание базовых разрешений
    permissions_data = [
        # Управление пользователями
        {'name': 'view_users', 'description': 'Просмотр списка пользователей', 'category': 'Управление пользователями'},
        {'name': 'add_users', 'description': 'Добавление новых пользователей', 'category': 'Управление пользователями'},
        {'name': 'edit_users', 'description': 'Редактирование пользователей', 'category': 'Управление пользователями'},
        {'name': 'delete_users', 'description': 'Удаление пользователей', 'category': 'Управление пользователями'},
        {'name': 'manage_users', 'description': 'Полное управление пользователями',
         'category': 'Управление пользователями'},

        # Управление ролями и разрешениями
        {'name': 'view_roles', 'description': 'Просмотр списка ролей', 'category': 'Управление ролями'},
        {'name': 'manage_roles', 'description': 'Управление ролями (создание, редактирование, удаление)',
         'category': 'Управление ролями'},
        {'name': 'view_permissions', 'description': 'Просмотр списка разрешений', 'category': 'Управление ролями'},
        {'name': 'manage_permissions', 'description': 'Управление разрешениями', 'category': 'Управление ролями'},

        # Аудит и логи
        {'name': 'view_logs', 'description': 'Просмотр логов аудита', 'category': 'Аудит'},

        # Обфускация
        {'name': 'use_obfuscation', 'description': 'Использование функции обфускации', 'category': 'Обфускация'},
        {'name': 'advanced_obfuscation', 'description': 'Расширенные функции обфускации', 'category': 'Обфускация'},

        # Общие
        {'name': 'change_password', 'description': 'Смена пароля', 'category': 'Общие'},
        {'name': 'view_dashboard', 'description': 'Просмотр главной страницы', 'category': 'Общие'},
    ]

    created_permissions = 0
    for perm_data in permissions_data:
        if not Permission.query.filter_by(name=perm_data['name']).first():
            permission = Permission(
                name=perm_data['name'],
                description=perm_data['description'],
                category=perm_data['category']
            )
            db.session.add(permission)
            created_permissions += 1
            print(f"Создано разрешение: {perm_data['name']}")

    db.session.commit()
    print(f"Создано {created_permissions} разрешений")

    # Создание базовых ролей
    # Роль администратора
    if not Role.query.filter_by(name='admin').first():
        admin_role = Role(name='admin', description='Полный доступ ко всем функциям системы')

        # Назначаем все разрешения администратору
        all_permissions = Permission.query.all()
        admin_role.permissions = all_permissions
        db.session.add(admin_role)
        print("Создана роль: admin")

    # Роль обычного пользователя
    if not Role.query.filter_by(name='user').first():
        user_role = Role(name='user', description='Обычный пользователь')
        basic_permissions = Permission.query.filter(
            Permission.name.in_(['use_obfuscation', 'change_password', 'view_dashboard'])
        ).all()
        user_role.permissions = basic_permissions
        db.session.add(user_role)
        print("Создана роль: user")

    # Роль аудитора
    if not Role.query.filter_by(name='auditor').first():
        auditor_role = Role(name='auditor', description='Аудитор - просмотр логов')
        auditor_permissions = Permission.query.filter(
            Permission.name.in_(['view_logs', 'view_dashboard'])
        ).all()
        auditor_role.permissions = auditor_permissions
        db.session.add(auditor_role)
        print("Создана роль: auditor")

    # Роль специалиста по обфускации
    if not Role.query.filter_by(name='obfuscator').first():
        obfuscator_role = Role(name='obfuscator', description='Специалист по обфускации')
        obfuscator_permissions = Permission.query.filter(
            Permission.name.in_(['use_obfuscation', 'advanced_obfuscation', 'change_password', 'view_dashboard'])
        ).all()
        obfuscator_role.permissions = obfuscator_permissions
        db.session.add(obfuscator_role)
        print("Создана роль: obfuscator")

    db.session.commit()
    print("Инициализация ролей и разрешений завершена")

    # Создаем базовые роли
    if not Role.query.filter_by(name='admin').first():
        admin_role = Role(name='admin', description='Полный доступ ко всем функциям системы')
        # Назначаем все разрешения администратору
        all_permissions = Permission.query.all()
        admin_role.permissions = all_permissions
        db.session.add(admin_role)

    if not Role.query.filter_by(name='user').first():
        user_role = Role(name='user', description='Обычный пользователь')
        # Базовые разрешения для пользователя
        basic_permissions = ['use_obfuscation', 'change_password', 'view_dashboard']
        permissions = Permission.query.filter(Permission.name.in_(basic_permissions)).all()
        user_role.permissions = permissions
        db.session.add(user_role)

    if not Role.query.filter_by(name='auditor').first():
        auditor_role = Role(name='auditor', description='Аудитор - просмотр логов')
        auditor_permissions = ['view_logs', 'view_dashboard']
        permissions = Permission.query.filter(Permission.name.in_(auditor_permissions)).all()
        auditor_role.permissions = permissions
        db.session.add(auditor_role)

    if not Role.query.filter_by(name='obfuscator').first():
        obfuscator_role = Role(name='obfuscator', description='Специалист по обфускации')
        obfuscator_permissions = ['use_obfuscation', 'advanced_obfuscation', 'change_password', 'view_dashboard']
        permissions = Permission.query.filter(Permission.name.in_(obfuscator_permissions)).all()
        obfuscator_role.permissions = permissions
        db.session.add(obfuscator_role)

    db.session.commit()


# Создание админа
def create_default_admin():
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("admin")
        admin.must_change_password = True
        admin.password_changed_at = datetime.now(timezone.utc)
        db.session.add(admin)
        db.session.commit()
        print("Создан админ.\nЛогин: admin\nПароль: admin")


# Инициализируем БД
with app.app_context():
    db.create_all()
    initialize_roles_and_permissions()
    create_default_admin()


# Главная страница
@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
