#!/usr/bin/env python3
"""Encrypting Password"""

import bcrypt


def hash_password(password: str) -> bytes:
    """Hashing function"""
    passwd = bytes(password, encoding='utf-8')
    return bcrypt.hashpw(passwd, bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Checks if provided password is valid"""
    passwd = bytes(password, encoding='utf-8')
    if bcrypt.checkpw(passwd, hashed_password):
        return True
    return False
