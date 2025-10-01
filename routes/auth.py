from flask import Blueprint, render_template, request, redirect, session, flash
from models import User, db
from datetime import timezone, datetime
from utils import is_password_strong, is_password_expired
import random
import string


# Создаём новый бп и указываем ему путь к папке с html-шаблонами
auth_bp = Blueprint("auth", __name__, template_folder="../templates")


# Функция для генерации случайного пароля
def generate_random_password(length=8):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choice(chars) for _ in range(length))


# Страница с авторизацией
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    # Получаем логин и пароль от пользователя
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Ищём совпадения в БД
        user = User.query.filter_by(username=username).first()

        # Проверяем есть ли такой пользователь и верный ли пароль
        if user and user.check_password(password):
            session["user_id"] = user.id

            # Проверяем, нужно ли сменить пароль
            if user.must_change_password:
                flash("Вы должны сменить пароль при первом входе")
                return redirect("/change_password")

            # Проверяем срок действия пароля
            if is_password_expired(user):
                flash("Срок действия пароля истёк. Пожалуйста, смените пароль")
                return redirect("/change_password")

        else:
            flash("Неверный логин или пароль")

    return render_template("login.html")


# Страница с добавлением нового пользователя (Доступно только админу)
@auth_bp.route("/add_user", methods=["GET", "POST"])
def add_user():
    # Проверяем есть ли сессия
    if "user_id" not in session:
        return redirect("/login")

    # Проверяем админ или нет
    current_user = User.query.get(session["user_id"])
    if current_user.role != "admin":
        flash("Только администратор может создавать пользователя")
        return redirect("/")

    # Получаем от админа из формы логин и пароль
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Проверяем, что логин не занят
        if User.query.filter_by(username=username).first():
            flash("Такой логин есть. Напишите другой")
            return redirect("/add_user")

        # Проверяем сложность пароля
        if not is_password_strong(password):
            flash("Пароль должен быть минимум 8 символов, содержать цифру, букву и спецсимвол !@#$%^&*")
            return redirect("/add_user")

        # Создаём нового пользователя
        new_user = User(username=username)
        new_user.set_password(password)
        new_user.must_change_password = True
        new_user.password_changed_at = datetime.now(timezone.utc)

        # Заводим сессию
        db.session.add(new_user)
        db.session.commit()
        flash(f"Пользователь {username} создан! Начальный пароль: {password}")
        return redirect("/users")

    return render_template("add_user.html")


# Страница (мини-админка) со списком пользователей, редактированием и удалением
@auth_bp.route("/users")
def list_users():
    # Проверяем авторизацию
    if "user_id" not in session:
        return redirect("/login")

    # Проверяем админ или нет
    current_user = User.query.get(session["user_id"])
    if current_user.role != "admin":
        flash("Только администратор может просматривать пользователей")
        return redirect("/")

    users = User.query.all()
    return render_template("users.html", users=users)


# Страница редактирования пользователя
@auth_bp.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):
    # Проверяем есть ли сессия
    if "user_id" not in session:
        return redirect("/login")

    # Проверяем админ или нет
    current_user = User.query.get(session["user_id"])
    if current_user.role != "admin":
        flash("Только администратор может редактировать пользователей")
        return redirect("/")

    user = User.query.get_or_404(user_id)

    # Редактирование логина
    if request.method == "POST":
        new_username = request.form.get("username")
        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                flash("Такой логин уже занят")
                return redirect(f"/edit_user/{user.id}")
            user.username = new_username

        # Проверяем, была ли нажата кнопка для случайного пароля
        if "set_random_password" in request.form:
            password = generate_random_password()
        else:
            password = request.form.get("password")

        # Проверяем сложность пароля
        if not is_password_strong(password):
            flash("Пароль должен быть минимум 8 символов, содержать цифру, букву и спецсимвол !@#$%^&*")
            return redirect(f"/edit_user/{user.id}")

        if password:
            user.set_password(password)
            user.must_change_password = True
            user.password_changed_at = datetime.now(timezone.utc)
            flash(f"Пароль пользователя {user.username} сброшен. Новый пароль: {password}")

        db.session.commit()
        return redirect("/users")

    return render_template("edit_user.html", user=user)


# Удаление пользователя (Не рендерим ничего, возвращаем на страницу со списком пользователей)
@auth_bp.route("/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    # Проверяем есть ли сессия
    if "user_id" not in session:
        return redirect("/login")

    # Проверяем админ или нет
    current_user = User.query.get(session["user_id"])
    if current_user.role != "admin":
        flash("Только администратор может удалять пользователей")
        return redirect("/users")

    user = User.query.get_or_404(user_id)

    # Чтобы админ случайно не удалил себя
    if user.id == current_user.id:
        flash("Нельзя удалить самого себя!")
        return redirect("/users")

    db.session.delete(user)
    db.session.commit()
    flash(f"Пользователь {user.username} удалён")
    return redirect("/users")


# Выход из системы (Не рендерим ничего, возвращаем на страницу со списком пользователей)
@auth_bp.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Вы вышли из системы")
    return redirect("/")


# Страница с изменением пароля
@auth_bp.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect("/login")

    user = User.query.get(session["user_id"])

    if request.method == "POST":
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Проверка совпадения паролей
        if new_password != confirm_password:
            flash("Пароли не совпадают")
            return redirect("/change_password")

        # Проверка сложности пароля
        if not is_password_strong(new_password):
            flash("Пароль должен быть минимум 8 символов, содержать цифру, букву и спецсимвол !@#$%^&*")
            return redirect("/change_password")

        # Сохраняем новый пароль
        user.set_password(new_password)
        user.must_change_password = False
        user.password_changed_at = datetime.now(timezone.utc)
        db.session.commit()
        flash("Пароль успешно изменён")
        return redirect("/")

    return render_template("change_password.html")
