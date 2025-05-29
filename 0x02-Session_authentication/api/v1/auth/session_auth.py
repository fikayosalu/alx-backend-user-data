#!/usr/bin/env python3
""" session_auth """

from api.v1.auth.auth import Auth
from uuid import uuid4


class SessionAuth(Auth):
    """ Session Authentication Class"""
    user_id_by_session_id = {}

    def __init__(self):
        pass

    def create_session(self, user_id: str = None) -> str:
        """ Creates a sessionId for a user_id
        Return:
        None if there is no user_id
        The sessionId created if there is a user_id
        """
        if user_id is None:
            return None
        if not isinstance(user_id, str):
            return None

        sessionId = str(uuid4())
        SessionAuth.user_id_by_session_id[sessionId] = user_id
        return sessionId

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ Returns a user_id based on a session """
        if session_id is None:
            return None
        if not isinstance(session_id, str):
            return None

        return SessionAuth.user_id_by_session_id.get(session_id)
