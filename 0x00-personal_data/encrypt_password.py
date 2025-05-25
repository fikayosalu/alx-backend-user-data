#!/usr/bin/env python3
""" encrypt_password """

import bcrypt

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt with a generated salt.

    Args:
        password (str): The plain-text password to hash.

    Returns:
        bytes: The salted, hashed password.
    """
    # Generate salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validate if the provided password matches the hashed password.

    Args:
        hashed_password (bytes): The stored hashed password.
        password (str): The plain-text password to verify.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
