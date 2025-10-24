from flask import Blueprint, request, redirect, session, flash, jsonify, render_template
from models import User, AuditLog
from datetime import datetime
from logging_system import audit_logger


# Создаем новый Blueprint для аудита
audit_bp = Blueprint("audit", __name__, template_folder="../templates")


@audit_bp.route("/logs")
def audit_logs():
    """Страница просмотра логов аудита"""
    if "user_id" not in session:
        return redirect("/login")

    current_user = User.query.get(session["user_id"])
    if current_user.role != "admin":
        flash("Только администратор может просматривать логи")
        return redirect("/")

    # Получаем логи из базы данных
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()

    audit_logger.log_action(
        action_type="view_audit_logs",
        status="success",
        message="Просмотр логов аудита"
    )

    return render_template("logs.html", logs=logs)


@audit_bp.route("/api/audit_logs")
def api_audit_logs():
    """API для получения логов (можно использовать для фильтрации)"""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    current_user = User.query.get(session["user_id"])
    if current_user.role != "admin":
        return jsonify({"error": "Forbidden"}), 403

    # Параметры фильтрации
    username = request.args.get('username')
    action_type = request.args.get('action_type')
    status = request.args.get('status')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    query = AuditLog.query

    if username:
        query = query.filter(AuditLog.username == username)
    if action_type:
        query = query.filter(AuditLog.action_type == action_type)
    if status:
        query = query.filter(AuditLog.status == status)
    if date_from:
        query = query.filter(AuditLog.timestamp >= datetime.fromisoformat(date_from))
    if date_to:
        query = query.filter(AuditLog.timestamp <= datetime.fromisoformat(date_to))

    logs = query.order_by(AuditLog.timestamp.desc()).limit(500).all()

    return jsonify([log.to_dict() for log in logs])