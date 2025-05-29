#!/usr/bin/env python3
""" Auth """

from flask import request
from typing import List, TypeVar
import os


class Auth:
    """ Authorization Class """
    def __init__(self):
        """ Initialize an instance of class auth """
        pass

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if a path requires authentication.
        Returns:
        bool: True if auth is required, False otherwise.
        """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != "/":
            path += "/"
        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the Authorization header from the request.
        Returns:
        str: The value of the Authorization header, or None if unavailable.
        """
        if request is None or "Authorization" not in request.headers:
            return None
        else:
            return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current authenticated user.
        Returns:
        User: The authenticated user object or None.
        """
        return None

    def session_cookie(self, request=None):
        """ Returns a cookie value from a request """
        cookie_name = os.getenv("SESSION_NAME")
        if request is None:
            return None
        return request.cookies.get(cookie_name)
