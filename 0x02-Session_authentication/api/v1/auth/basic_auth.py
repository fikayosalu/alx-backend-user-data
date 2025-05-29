#!/usr/bin/env python3
""" basic_auth """
import base64
from api.v1.auth.auth import Auth
from models.user import User
from typing import TypeVar

UserType = TypeVar('User')


class BasicAuth(Auth):
    """ Basic Authorization """
    def __init__(self):
        """Initialize BasicAuth (inherited from Auth)"""
        pass

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Extracts the Base64 part from the Authorization header.
        Returns:
            str: The Base64 part or None if invalid.
        """
        if authorization_header is None or not isinstance(
                                                authorization_header, str):
            return None
        items = authorization_header.split(" ")
        if len(items) != 2 or items[0] != "Basic":
            return None
        return items[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes a Base64-encoded authorization header string.
        Returns:
            str: The decoded UTF-8 string if valid, otherwise None.
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(
                base64_authorization_header, validate=True)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Extracts user email and password from a Base64 decoded string.
        Returns:
            tuple: (user_email, user_password) or (None, None) if invalid.
        """
        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        email, password = decoded_base64_authorization_header.split(':', 1)
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> UserType:
        """
        Retrieves the User instance matching the given email and password.
        Returns:
            User: The authenticated user object or None.
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({"email": user_email})
        except Exception:
            return None

        if not users or len(users) == 0:
            return None

        user = users[0]

        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> User:
        """
        Retrieves the User instance for a request using Basic Authentication.
        Returns:
            User: The authenticated user object or None.
        """
        if request is None:
            return None

        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None

        base64_header = self.extract_base64_authorization_header(auth_header)
        if base64_header is None:
            return None

        decoded_header = self.decode_base64_authorization_header(base64_header)
        if decoded_header is None:
            return None

        email, password = self.extract_user_credentials(decoded_header)
        if email is None or password is None:
            return None

        return self.user_object_from_credentials(email, password)
