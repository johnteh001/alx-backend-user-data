#!/usr/bin/env python3
"""Authentication
"""

from flask import request
from typing import List, TypeVar
import os


class Auth:
    """Authentication class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """authorizes paths
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path and path[-1] != "/":
            path = path + "/"
        if path and path not in excluded_paths:
            return True
        else:
            return False

    def authorization_header(self, request=None) -> str:
        """auth header
        """
        if request is None:
            return None
        value = request.headers.get('Authorization')
        if value:
            return value
        else:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """current user
        """
        return None

    def session_cookie(self, request=None):
        """Returns a cookie value from a request
        """
        cookie_name = os.getenv('SESSION_NAME', None)
        if request:
            if cookie_name:
                return request.cookies.get(cookie_name)
        return None
