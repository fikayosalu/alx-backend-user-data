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
