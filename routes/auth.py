from flask import Blueprint, render_template, request, redirect, session, flash
from models import User, db
from datetime import timezone, datetime
from utils import is_password_strong, is_password_expired
from logging_system import audit_logger
import random
import string


auth_bp = Blueprint("auth", __name__, template_folder="../templates")


def generate_random_password(length=8):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choice(chars) for _ in range(length))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session["user_id"] = user.id

            # Логируем успешный вход
            audit_logger.log_action(
                action_type="login",
                status="success",
                message="Успешная аутентификация",
                username=username
            )

            if user.must_change_password:
                flash("Вы должны сменить пароль при первом входе")
                return redirect("/change_password")

            if is_password_expired(user):
                flash("Срок действия пароля истёк. Пожалуйста, смените пароль")
                return redirect("/change_password")

            flash("Вход выполнен успешно")
            return redirect("/")
        else:
            # Логируем неудачную попытку входа
            audit_logger.log_action(
                action_type="login",
                status="failed",
                message="Неверный логин или пароль",
                username=username
            )
            flash("Неверный логин или пароль")

    return render_template("login.html")


@auth_bp.route("/add_user", methods=["GET", "POST"])
def add_user():
    if "user_id" not in session:
        return redirect("/login")

    current_user = User.query.get(session["user_id"])
    if current_user.role != "admin":
        audit_logger.log_action(
            action_type="add_user",
            status="failed",
            message="Попытка создания пользователя без прав администратора"
        )
        flash("Только администратор может создавать пользователя")
        return redirect("/")

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if User.query.filter_by(username=username).first():
            audit_logger.log_action(
                action_type="add_user",
                status="failed",
                message=f"Попытка создания пользователя с существующим логином: {username}"
            )
            flash("Такой логин есть. Напишите другой")
            return redirect("/add_user")

        if not is_password_strong(password):
            audit_logger.log_action(
                action_type="add_user",
                status="failed",
                message="Попытка создания пользователя со слабым паролем"
            )
            flash("Пароль должен быть минимум 8 символов, содержать цифру, букву и спецсимвол !@#$%^&*")
            return redirect("/add_user")

        new_user = User(username=username)
        new_user.set_password(password)
        new_user.must_change_password = True
        new_user.password_changed_at = datetime.now(timezone.utc)

        db.session.add(new_user)
        db.session.commit()

        audit_logger.log_action(
            action_type="add_user",
            status="success",
            message=f"Создан пользователь: {username}"
        )
        flash(f"Пользователь {username} создан! Начальный пароль: {password}")
        return redirect("/users")

    return render_template("add_user.html")


@auth_bp.route("/users")
def list_users():
    if "user_id" not in session:
        return redirect("/login")

    current_user = User.query.get(session["user_id"])
    if current_user.role != "admin":
        audit_logger.log_action(
            action_type="view_users",
            status="failed",
            message="Попытка просмотра списка пользователей без прав администратора"
        )
        flash("Только администратор может просматривать пользователей")
        return redirect("/")

    audit_logger.log_action(
        action_type="view_users",
        status="success",
        message="Просмотр списка пользователей"
    )
    users = User.query.all()
    return render_template("users.html", users=users)


@auth_bp.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):
    if "user_id" not in session:
        return redirect("/login")

    current_user = User.query.get(session["user_id"])
    if current_user.role != "admin":
        audit_logger.log_action(
            action_type="edit_user",
            status="failed",
            message="Попытка редактирования пользователя без прав администратора"
        )
        flash("Только администратор может редактировать пользователей")
        return redirect("/")

    user = User.query.get_or_404(user_id)

    if request.method == "POST":
        new_username = request.form.get("username")
        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                audit_logger.log_action(
                    action_type="edit_user",
                    status="failed",
                    message=f"Попытка изменения логина на существующий: {new_username}"
                )
                flash("Такой логин уже занят")
                return redirect(f"/edit_user/{user.id}")
            user.username = new_username

        if "set_random_password" in request.form:
            password = generate_random_password()
        else:
            password = request.form.get("password")

        if password and not is_password_strong(password):
            audit_logger.log_action(
                action_type="edit_user",
                status="failed",
                message="Попытка установки слабого пароля при редактировании пользователя"
            )
            flash("Пароль должен быть минимум 8 символов, содержать цифру, букву и спецсимвол !@#$%^&*")
            return redirect(f"/edit_user/{user.id}")

        if password:
            user.set_password(password)
            user.must_change_password = True
            user.password_changed_at = datetime.now(timezone.utc)

            audit_logger.log_action(
                action_type="edit_user",
                status="success",
                message=f"Пароль пользователя {user.username} сброшен"
            )
            flash(f"Пароль пользователя {user.username} сброшен. Новый пароль: {password}")

        db.session.commit()

        audit_logger.log_action(
            action_type="edit_user",
            status="success",
            message=f"Пользователь {user.username} отредактирован"
        )
        return redirect("/users")

    return render_template("edit_user.html", user=user)


@auth_bp.route("/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "user_id" not in session:
        return redirect("/login")

    current_user = User.query.get(session["user_id"])
    if current_user.role != "admin":
        audit_logger.log_action(
            action_type="delete_user",
            status="failed",
            message="Попытка удаления пользователя без прав администратора"
        )
        flash("Только администратор может удалять пользователей")
        return redirect("/users")

    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        audit_logger.log_action(
            action_type="delete_user",
            status="failed",
            message="Попытка удаления собственного аккаунта"
        )
        flash("Нельзя удалить самого себя!")
        return redirect("/users")

    db.session.delete(user)
    db.session.commit()

    audit_logger.log_action(
        action_type="delete_user",
        status="success",
        message=f"Пользователь {user.username} удален"
    )
    flash(f"Пользователь {user.username} удалён")
    return redirect("/users")


@auth_bp.route("/logout")
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        username = user.username if user else 'unknown'

        audit_logger.log_action(
            action_type="logout",
            status="success",
            message="Выход из системы",
            username=username
        )

    session.pop("user_id", None)
    flash("Вы вышли из системы")
    return redirect("/")


@auth_bp.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect("/login")

    user = User.query.get(session["user_id"])

    if request.method == "POST":
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            audit_logger.log_action(
                action_type="change_password",
                status="failed",
                message="Пароли не совпадают"
            )
            flash("Пароли не совпадают")
            return redirect("/change_password")

        if not is_password_strong(new_password):
            audit_logger.log_action(
                action_type="change_password",
                status="failed",
                message="Попытка установки слабого пароля"
            )
            flash("Пароль должен быть минимум 8 символов, содержать цифру, букву и спецсимвол !@#$%^&*")
            return redirect("/change_password")

        user.set_password(new_password)
        user.must_change_password = False
        user.password_changed_at = datetime.now(timezone.utc)
        db.session.commit()

        audit_logger.log_action(
            action_type="change_password",
            status="success",
            message="Пароль успешно изменен"
        )
        flash("Пароль успешно изменён")
        return redirect("/")

    return render_template("change_password.html")

