#!/usr/bin/env python3
"""Hash Password
"""
import bcrypt
from user import User
from db import DB
import uuid
from typing import TypeVar, Union
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Hashes password and return
    """
    str_byte = bytes(password, encoding='utf-8')
    hashed = bcrypt.hashpw(str_byte, bcrypt.gensalt())
    return hashed


def _generate_uuid() -> str:
    """Function return string representation of new UUID
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> TypeVar('User'):
        """Perform user registration
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        else:
            raise ValueError('User {} already exists'.format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """Credentials validation
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        else:
            if user:
                passw = bytes(password, encoding="utf-8")
                if bcrypt.checkpw(passw, user.hashed_password):
                    return True
            return False

    def create_session(self, email: str) -> str:
        """Find the user for the email, generate new UUID, and store it
        in the database as user's session_id, then return session_id
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            pass
        else:
            if user:
                u_id = _generate_uuid()
                self._db.update_user(user.id, session_id=u_id)
                return u_id

    def get_user_from_session_id(self, session_id: str) -> Union[
            TypeVar('User'), None]:
        """Function finds user by session ID
        """
        if session_id:
            try:
                user = self._db.find_user_by(session_id=session_id)
            except NoResultFound:
                return None
            else:
                return user
        return None

    def destroy_session(self, user_id: int) -> None:
        """Function updates session Id to none
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            pass
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Function generates and updates reset_token in database
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        else:
            token = str(uuid.uuid4())
            self._db.update_user(user.id, reset_token=token)
            return token

    def update_password(self, reset_token: str, password: str):
        """Resets the password of the user
        """
        if reset_token and password:
            try:
                user = self._db.find_user_by(reset_token=reset_token)
            except NoResultFound:
                raise ValueError
            else:
                hashpw = _hash_password(password)
                di = {"hashed_password": hashpw, "reset_token": None}
                self._db.update_user(user.id, **di)
        return None
