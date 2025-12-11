import logging
import os
from datetime import datetime
from flask import request, session
from models import User, db, AuditLog


class AuditLogger:
    def __init__(self, app=None):
        self.logger = None
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        # Создание папки для логов
        if not os.path.exists('logs'):
            os.makedirs('logs')

        # Настройка формата логирования
        log_format = '%(asctime)s | %(audit_username)s | %(audit_action)s | %(audit_status)s | %(audit_msg)s'

        # Настройка файлового обработчика
        file_handler = logging.FileHandler('logs/audit.log', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)

        # Создание логгера
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)

        # Отключение дублирования
        self.logger.propagate = False

    def log_action(self, action_type, status, message='', username=None):
        # Запись действия в лог
        if not username:
            username = self._get_current_username()

        extra = {
            'audit_username': username,
            'audit_action': action_type,
            'audit_status': status,
            'audit_msg': message
        }

        self.logger.info('Audit action', extra=extra)

        # Сохранение в БД
        self._save_to_database(action_type, status, message, username)

    def _get_current_username(self):
        # Получение имени текущего пользователя
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            return user.username if user else 'unknown'
        return 'anonymous'

    def _save_to_database(self, action_type, status, message, username):
        # Сохранение записи в БД
        try:
            log_entry = AuditLog(
                username=username,
                action_type=action_type,
                timestamp=datetime.now(),
                status=status,
                message=message,
                ip_address=request.remote_addr if request else 'N/A'
            )
            db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            print(f"Ошибка отправки лога в БД: {str(e)}")

audit_logger = AuditLogger()