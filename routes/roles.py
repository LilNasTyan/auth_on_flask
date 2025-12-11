from flask import Blueprint, render_template, request, jsonify
from models import db, User, Role, Permission
from logging_system import audit_logger
from utils import permission_required

roles_bp = Blueprint("roles", __name__, template_folder="../templates")


@roles_bp.route("/roles")
@permission_required('view_roles')
def list_roles():
    roles = Role.query.all()
    permissions = Permission.query.all()

    permissions_by_category = {}
    for perm in permissions:
        category = perm.category or "Общие"
        if category not in permissions_by_category:
            permissions_by_category[category] = []
        permissions_by_category[category].append(perm)

    permissions_by_category_list = []
    for category, perms in permissions_by_category.items():
        permissions_by_category_list.append({
            'category': category,
            'permissions': perms
        })

    audit_logger.log_action(
        action_type="view_roles",
        status="success",
        message="Просмотр списка ролей"
    )

    return render_template("roles.html",
                           roles=roles,
                           permissions_by_category=permissions_by_category_list)


@roles_bp.route("/api/roles", methods=["POST"])
@permission_required('manage_roles')
def create_role():
    data = request.get_json()

    if not data or 'name' not in data:
        return jsonify({"error": "Не указано название роли"}), 400

    name = data['name'].strip()
    description = data.get('description', '').strip()

    if Role.query.filter_by(name=name).first():
        return jsonify({"error": "Роль с таким названием уже существует"}), 400

    role = Role(name=name, description=description)

    if 'permissions' in data:
        permission_ids = data['permissions']
        permissions = Permission.query.filter(Permission.id.in_(permission_ids)).all()
        role.permissions = permissions

    db.session.add(role)
    db.session.commit()

    audit_logger.log_action(
        action_type="create_role",
        status="success",
        message=f"Создана роль: {name}"
    )

    return jsonify({
        "success": True,
        "message": f"Роль '{name}' создана",
        "role": role.to_dict()
    })


@roles_bp.route("/api/roles/<int:role_id>", methods=["PUT"])
@permission_required('manage_roles')
def update_role(role_id):
    role = Role.query.get_or_404(role_id)
    data = request.get_json()

    if 'name' in data:
        new_name = data['name'].strip()
        if new_name != role.name:
            existing = Role.query.filter_by(name=new_name).first()
            if existing and existing.id != role.id:
                return jsonify({"error": "Роль с таким названием уже существует"}), 400
            role.name = new_name

    if 'description' in data:
        role.description = data['description'].strip()

    if 'permissions' in data:
        permission_ids = data['permissions']
        permissions = Permission.query.filter(Permission.id.in_(permission_ids)).all()
        role.permissions = permissions

    db.session.commit()

    audit_logger.log_action(
        action_type="update_role",
        status="success",
        message=f"Обновлена роль: {role.name}"
    )

    return jsonify({
        "success": True,
        "message": f"Роль '{role.name}' обновлена",
        "role": role.to_dict()
    })


@roles_bp.route("/api/roles/<int:role_id>", methods=["DELETE"])
@permission_required('manage_roles')
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)

    if role.name in ['admin', 'user']:
        return jsonify({"error": "Нельзя удалять системные роли"}), 400

    if role.users.count() > 0:
        return jsonify({"error": "Нельзя удалить роль, назначенную пользователям"}), 400

    role_name = role.name
    db.session.delete(role)
    db.session.commit()

    audit_logger.log_action(
        action_type="delete_role",
        status="success",
        message=f"Удалена роль: {role_name}"
    )

    return jsonify({
        "success": True,
        "message": f"Роль '{role_name}' удалена"
    })


@roles_bp.route("/api/roles/<int:role_id>/assign", methods=["POST"])
@permission_required('manage_users')
def assign_role_to_user(role_id):
    data = request.get_json()

    if not data or 'user_id' not in data:
        return jsonify({"error": "Не указан пользователь"}), 400

    role = Role.query.get_or_404(role_id)
    user = User.query.get_or_404(data['user_id'])

    if role in user.roles:
        return jsonify({"error": "Эта роль уже назначена пользователю"}), 400

    user.roles.append(role)
    db.session.commit()

    audit_logger.log_action(
        action_type="assign_role",
        status="success",
        message=f"Роль '{role.name}' назначена пользователю '{user.username}'"
    )

    return jsonify({
        "success": True,
        "message": f"Роль '{role.name}' назначена пользователю '{user.username}'"
    })


@roles_bp.route("/api/roles/<int:role_id>/revoke", methods=["POST"])
@permission_required('manage_users')
def revoke_role_from_user(role_id):
    data = request.get_json()

    if not data or 'user_id' not in data:
        return jsonify({"error": "Не указан пользователь"}), 400

    role = Role.query.get_or_404(role_id)
    user = User.query.get_or_404(data['user_id'])

    if role not in user.roles:
        return jsonify({"error": "Эта роль не назначена пользователю"}), 400

    if len(user.roles) <= 1:
        return jsonify({"error": "Нельзя отозвать последнюю роль у пользователя"}), 400

    user.roles.remove(role)
    db.session.commit()

    audit_logger.log_action(
        action_type="revoke_role",
        status="success",
        message=f"Роль '{role.name}' отозвана у пользователя '{user.username}'"
    )

    return jsonify({
        "success": True,
        "message": f"Роль '{role.name}' отозвана у пользователя '{user.username}'"
    })


@roles_bp.route("/permissions")
@permission_required('view_permissions')
def list_permissions():
    permissions = Permission.query.all()

    permissions_by_category = {}
    for perm in permissions:
        category = perm.category or "Общие"
        if category not in permissions_by_category:
            permissions_by_category[category] = []
        permissions_by_category[category].append(perm)

    permissions_by_category_list = []
    for category, perms in permissions_by_category.items():
        permissions_by_category_list.append({
            'category': category,
            'permissions': perms
        })

    audit_logger.log_action(
        action_type="view_permissions",
        status="success",
        message="Просмотр списка разрешений"
    )

    return render_template("permissions.html",
                           permissions_by_category=permissions_by_category_list)


@roles_bp.route("/api/permissions", methods=["POST"])
@permission_required('manage_permissions')
def create_permission():
    data = request.get_json()

    if not data or 'name' not in data:
        return jsonify({"error": "Не указано название разрешения"}), 400

    name = data['name'].strip()
    description = data.get('description', '').strip()
    category = data.get('category', '').strip()

    if Permission.query.filter_by(name=name).first():
        return jsonify({"error": "Разрешение с таким названием уже существует"}), 400

    permission = Permission(name=name, description=description, category=category)
    db.session.add(permission)
    db.session.commit()

    audit_logger.log_action(
        action_type="create_permission",
        status="success",
        message=f"Создано разрешение: {name}"
    )

    return jsonify({
        "success": True,
        "message": f"Разрешение '{name}' создано",
        "permission": permission.to_dict()
    })


@roles_bp.route("/api/permissions/<int:permission_id>", methods=["DELETE"])
@permission_required('manage_permissions')
def delete_permission(permission_id):
    permission = Permission.query.get_or_404(permission_id)

    if permission.roles.count() > 0:
        return jsonify({"error": "Нельзя удалить разрешение, которое используется в ролях"}), 400

    permission_name = permission.name
    db.session.delete(permission)
    db.session.commit()

    audit_logger.log_action(
        action_type="delete_permission",
        status="success",
        message=f"Удалено разрешение: {permission_name}"
    )

    return jsonify({
        "success": True,
        "message": f"Разрешение '{permission_name}' удалено"
    })


@roles_bp.route("/user/<int:user_id>/roles")
@permission_required('manage_users')
def manage_user_roles(user_id):
    user = User.query.get_or_404(user_id)
    all_roles = Role.query.all()

    return render_template("user_roles.html",
                           user=user,
                           all_roles=all_roles)


@roles_bp.route("/api/user/<int:user_id>/roles", methods=["POST"])
@permission_required('manage_users')
def update_user_roles(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    if not data or 'role_ids' not in data:
        return jsonify({"error": "Не указаны роли"}), 400

    role_ids = data['role_ids']
    new_roles = Role.query.filter(Role.id.in_(role_ids)).all()

    user.roles = new_roles
    db.session.commit()

    role_names = [role.name for role in new_roles]

    audit_logger.log_action(
        action_type="update_user_roles",
        status="success",
        message=f"Обновлены роли пользователя '{user.username}': {', '.join(role_names)}"
    )

    return jsonify({
        "success": True,
        "message": f"Роли пользователя '{user.username}' обновлены",
        "roles": role_names
    })