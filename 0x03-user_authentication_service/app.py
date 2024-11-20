#!/usr/bin/env python3
"""Basic Flask app
"""
from flask import Flask, jsonify, request, abort, url_for, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=['GET'], strict_slashes=False)
def index():
    """Basic message
    """
    return jsonify({"message": "Bienvenue"}), 200


@app.route("/users", methods=['POST'], strict_slashes=False)
def users():
    """Register a user
    """
    email = request.form.get("email")
    password = request.form.get("password")
    if email and password:
        try:
            user = AUTH.register_user(email, password)
            return jsonify({"email": user.email, "message": "user created"})
        except ValueError as e:
            return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """Implement user login
    """
    email = request.form.get("email")
    password = request.form.get("password")
    if email and password:
        if AUTH.valid_login(email, password):
            sess_id = AUTH.create_session(email)
            resp = jsonify({"email": email, "message": "logged in"})
            resp.set_cookie("session_id", sess_id)
            return resp
    abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """Logs the user out
    """
    sess_id = request.cookies.get("session_id")
    if sess_id:
        user = AUTH.get_user_from_session_id(sess_id)
        if user:
            AUTH.destroy_session(user.id)
            return redirect(url_for('index'))
    abort(403)


@app.route("/profile", methods=['GET'], strict_slashes=False)
def profile():
    """Finds if user in the database
    """
    sess_id = request.cookies.get("session_id")
    if sess_id:
        user = AUTH.get_user_from_session_id(sess_id)
        if user:
            return jsonify({"email": user.email}), 200
    abort(403)


@app.route("/reset_password", methods=['POST'], strict_slashes=False)
def get_rest_password_token():
    """Resets password token
    """
    email = request.form.get("email")
    if email:
        try:
            token = AUTH.get_reset_password_token(email)
        except ValueError:
            abort(403)
        else:
            return jsonify({"email": email, "reset_token": token}), 200


@app.route("/reset_password", methods=['PUT'], strict_slashes=False)
def update_password():
    """Implements password update in database
    """
    email = request.form.get("email")
    res_token = request.form.get("reset_token")
    new_pass = request.form.get("new_password")
    if res_token and new_pass and email:
        try:
            AUTH.update_password(res_token, new_pass)
        except ValueError:
            abort(403)
        else:
            return jsonify({"email": email, "message": "Password updated"})
    abort(400)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
