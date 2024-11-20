#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError


from user import Base, User
from typing import TypeVar


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> TypeVar('User'):
        """Adding new user to database
        """
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()
        return new_user

    def find_user_by(self, **kwargs) -> TypeVar('User'):
        """Finding user based on the keyword arguments
        """
        try:
            user = self._session.query(User).filter_by(**kwargs).first()
        except TypeError:
            raise InvalidRequestError
        if user is None:
            raise NoResultFound
        return user

    def update_user(self, user_id: int, **kwargs):
        """Method updates user information
        """
        user = self.find_user_by(id=user_id)
        for key, value in kwargs.items():
            if key in vars(user):
                setattr(user, key, value)
            else:
                raise ValueError
        self._session.commit()
        return None
