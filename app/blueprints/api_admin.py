from __future__ import annotations

from flask import Blueprint, jsonify
from flask_login import current_user, login_required

from app.models.user import User

api_admin_bp = Blueprint("api_admin", __name__)


@api_admin_bp.get("/users")
@login_required
def list_users():
    if not current_user.is_admin:
        return jsonify({"error": "Administrator access is required."}), 403
    users = User.query.order_by(User.username.asc()).all()
    return jsonify({"items": [{
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
    } for user in users]})
