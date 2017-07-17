"""
Main client module
"""
from typing import Optional

from . import exceptions
from .base import HTTPBase
from .secrets import BaseSecret
from .audit import BaseAudit
from .vault_sys import BaseSys
from .policy import BasePolicy
from .auth import BaseAuth


class VaultClient(HTTPBase):
    """
    Vault client, keeps a session and facilitates access to vault backends
    """
    def __init__(self, *args, **kwargs):
        super(VaultClient, self).__init__(*args, **kwargs)

        # If session is None then one would have been generated, pass that one round
        kwargs.pop('session', None)
        self.secrets = BaseSecret(*args, session=self.session, **kwargs)
        self.audit = BaseAudit(*args, session=self.session, **kwargs)
        self.sys = BaseSys(*args, session=self.session, **kwargs)
        self.policies = BasePolicy(*args, session=self.session, **kwargs)
        self.auth = BaseAuth(*args, session=self.session, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    async def is_authenticated(self) -> bool:
        """
        Attempt to call `auth/token/lookup-self`, if it's successful then return True and otherwise return False

        :return: True if token is valid, False otherwise
        """
        if self._auth_token is None:
            return False

        try:
            await self._get('auth/token/lookup-self')
            # If it doesnt raise an exception
            return True
        except exceptions.Forbidden:
            return False
        except exceptions.InvalidPath:
            return False
        except exceptions.InvalidRequest:
            return False

    def logout(self):
        """
        Removes the current token from the client
        """
        self._auth_token = None

    @property
    def auth_token(self) -> Optional[str]:
        """
        Get current auth token

        :return: Auth token
        """
        return self._auth_token

    @auth_token.setter
    def auth_token(self, token: str):
        """
        Set auth token

        :param token: Auth token
        """
        self._auth_token = token
