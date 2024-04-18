#!/usr/bin/env python3
"""SessionAuth Module"""
from flask import Flask, request, jsonify, abort, make_response
from api.v1.views import app_views
from models.user import User
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """ POST /api/v1/auth_session/login
    Return:
      - User object JSON represented
      - 404 if the User ID doesn't exist
      - 401 if the password is wrong
    """
    email = request.form.get('email')
    if email is None or email == "":
        return jsonify({"error": "email missing"}), 400

    password = request.form.get('password')
    if password is None or password == "":
        return jsonify({"error": "password missing"}), 400

    users = User.search({"email": email})
    if not users or len(users) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    for user in users:
        if user.is_valid_password(password):
            from api.v1.app import auth
            session_id = auth.create_session(user.id)
            response = make_response(user.to_json())
            response.set_cookie(os.getenv('SESSION_NAME'), session_id)
            return response

    return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout():
    """ DELETE /api/v1/auth_session/logout
    Return:
      - 200 on success
    """
    from api.v1.app import auth
    if auth.destroy_session(request):
        return jsonify({}), 200
    abort(404)
