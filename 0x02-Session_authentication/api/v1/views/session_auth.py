#!/usr/bin/env python3
"""Model for Session authentication
"""
from flask import abort, jsonify, request, session
from api.v1.views import app_views
from models.user import User
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def all_sess_routes() -> str:
    """Handle all session login
    """
    email = request.form.get("email")
    password = request.form.get("password")
    if email is None:
        return jsonify({"error": "email missing"}), 400
    if password is None:
        return jsonify({"error": "password missing"}), 400
    try:
        users = User.search({"email": email})
    except Exception as e:
        return jsonify({"error": "no user found for this email"}), 404
    if users is not None:
        for user in users:
            if user.is_valid_password(password):  # handle else
                from api.v1.app import auth
                sess_id = auth.create_session(user.id)
                res = jsonify(user.to_json())
                cookie_name = os.getenv("SESSION_NAME", None)
                if cookie_name:
                    res.set_cookie(cookie_name, sess_id)
                return res
            else:
                return jsonify({"error": "wrong password"}), 401
    return jsonify({"error": "no user found for this email"}), 404


@app_views.route("/auth_session/logout", methods=['DELETE'],
                 strict_slashes=False)
def remove_session():
    """Destroy session
    """
    from api.v1.app import auth
    if auth.destroy_session(request):
        return jsonify({}), 200
    abort(404)
