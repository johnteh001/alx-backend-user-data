#!/usr/bin/env python3
"""End-to-end integration test
"""
import requests


def register_user(email: str, password: str) -> None:
    """register user
    """
    url = "http://localhost:5000/users"
    user = {"email": email, "password": password}
    resp = requests.post(url, data=user)
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"email": email, "message": "user created"}


def log_in_wrong_password(email: str, password: str) -> None:
    """logs in wrong password
    """
    url = "http://localhost:5000/sessions"
    user = {"email": email, "password": password}
    resp = requests.post(url, data=user)
    assert resp.status_code == 401


def log_in(email: str, password: str) -> str:
    """logs in correctly
    """
    url = "http://localhost:5000/sessions"
    user = {"email": email, "password": password}
    resp = requests.post(url, data=user)
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "logged in"}
    return resp.cookies['session_id']


def profile_unlogged() -> None:
    """Tests non existing user profile
    """
    url = "http://localhost:5000/profile"
    cookies = dict(session_id="Unlogged")
    resp = requests.get(url, cookies=cookies)
    assert resp.status_code == 403


def profile_logged(session_id: str) -> None:
    """checks if the user exists in database
    """
    url = "http://localhost:5000/profile"
    cookies = dict(session_id=session_id)
    resp = requests.get(url, cookies=cookies)
    assert resp.status_code == 200


def log_out(session_id: str) -> None:
    """ Logs out the user
    """
    url = "http://localhost:5000/sessions"
    cookies = dict(session_id=session_id)
    resp = requests.delete(url, cookies=cookies)
    assert resp.status_code == 200
    assert resp.json() == {"message": "Bienvenue"}


def reset_password_token(email: str) -> str:
    """ Resets user password
    """
    url = "http://localhost:5000/reset_password"
    data = dict(email=email)
    resp = requests.post(url, data=data)
    assert resp.status_code == 200
    body = resp.json()
    return body["reset_token"]


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Resets user password
    """
    url = "http://localhost:5000/reset_password"
    data = {"email": email, "reset_token": reset_token,
            "new_password": new_password}
    resp = requests.put(url, data=data)
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "Password updated"}


EMAIL = "gullaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
