from flask import Flask, render_template
from dotenv import load_dotenv
from models import db, User
from datetime import datetime, timezone
from logging_system import audit_logger
import os
from routes.auth import auth_bp
from routes.logs import audit_bp
from routes.obfuscation import obfuscation_bp


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

# Создаём админа
def create_default_admin():
    # Проверяем есть ли админ
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
    create_default_admin()


# Главная страница
@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
