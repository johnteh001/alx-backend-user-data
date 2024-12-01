#!/usr/bin/env python3
"""BasicAuth module
"""

from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """BasicAuth class
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Returns base64 part of authorization header
        """
        auth_header = authorization_header
        if auth_header:
            if isinstance(auth_header, str):
                str_list = auth_header.split()
                if str_list[0] == "Basic":
                    value = ""
                    for i in range(1, len(str_list)):
                        if i < len(str_list) - 1:
                            value = value + str_list[i] + " "
                        else:
                            value = value + str_list[i]
                    return value
        return None

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """Returns the decoded value of Base64 string
        """
        if base64_authorization_header:
            if isinstance(base64_authorization_header, str):
                encoded_header = base64_authorization_header.encode('utf-8')
                try:
                    message = base64.b64decode(encoded_header).decode('utf-8')
                except Exception:
                    return None
                else:
                    return message
        return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        """Extracts user email and password from the decoded argument
        """
        if decoded_base64_authorization_header:
            if isinstance(decoded_base64_authorization_header, str):
                if ":" in decoded_base64_authorization_header:
                    dec_list = decoded_base64_authorization_header.split(":")
                    return (dec_list[0], dec_list[1])
        return (None, None)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """Returns User instance based on email and password
        """
        if user_email and user_pwd and isinstance(user_email,
                                                  str) and isinstance(user_pwd,
                                                                      str):
            try:
                objs = User.search({"email": user_email})
            except Exception:
                return None
            if objs:
                for obj in objs:
                    if obj.is_valid_password(user_pwd):
                        return obj
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Overloads Auth, and retrieves User instance for a request
        """
        header = self.authorization_header(request)
        if header:
            base64 = self.extract_base64_authorization_header(header)
            if base64:
                decoded = self.decode_base64_authorization_header(base64)
                if decoded:
                    email_pass = self.extract_user_credentials(decoded)
                    if email_pass:
                        user = self.user_object_from_credentials(
                                email_pass[0], email_pass[1])
                        return user
        return None
