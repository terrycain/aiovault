"""
Module containing secret backends
"""
from typing import Optional
from .base import HTTPBase, ResponseBase


class GenericSecretBackend(HTTPBase):
    """
    The generic secret backend

    By default will use the /secret path, if others exist then call :class:`BaseSecret.get_generic_secret_backend` to get a secret backend object for that path
    """
    def __init__(self, *args, mount_path: str='secret', **kwargs):
        super(GenericSecretBackend, self).__init__(*args, **kwargs)

        self._mount_path = mount_path

    async def mount(self, path: str, description: str='', default_lease_ttl: int=0, max_lease_ttl: int=0, force_no_cache: bool=False):
        """
        Mount the generic secret backend against the path

        :param path: Mount path
        :param description: Mount description
        :param default_lease_ttl: TTL
        :param max_lease_ttl: Max TTL
        :param force_no_cache: Force no caching

        :raises exceptions.VaultError: On error
        """
        payload = {
            'type': 'generic',
            'description': description,
            'config': {
                'default_lease_ttl': str(default_lease_ttl),
                'max_lease_ttl': str(max_lease_ttl),
                'force_no_cache': force_no_cache
            }
        }

        await self._post(['sys/mounts', path], payload=payload)

    async def create(self, path: str, **kwargs: dict):
        """
        Write generic secret to path, stores all keyword arguments.
        The Generic secret backend doesnt create renewable secrets afaik.
        ttl keyword argument will actually affect the TTL in vault

        :param path: Secret path
        :param kwargs: Keywork arguments

        :raises exceptions.VaultError: On error
        """
        await self._post([self._mount_path, path], payload=kwargs)

    async def update(self, path: str, **kwargs: dict):
        """
        Update will update arguments currently stored at path, overwiting any existing if specified in kwargs
        ttl keyword argument will actually affect the TTL in vault

        :param path: Secret path
        :param kwargs: Keywork arguments

        :raises exceptions.VaultError: On error
        """
        # Vault generic secret backend doesnt honour update so we will
        secret = await self.read(path)
        key_info = secret.data
        key_info.update(kwargs)

        await self._put([self._mount_path, path], payload=key_info)

    async def delete(self, path: str):
        """
        Delete key

        :param path: Secret path

        :raises exceptions.VaultError: On error
        """
        await self._delete([self._mount_path, path])

    async def read(self, path: str, wrap_ttl: Optional[int]=None) -> ResponseBase:
        """
        Read generic secret

        :param path: Secret path
        :param wrap_ttl: Wrap TTL
        :return: Response

        :raises exceptions.VaultError: On error
        """
        response = await self._get([self._mount_path, path], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def list(self, path: str, wrap_ttl: Optional[int]=None) -> ResponseBase:
        """
        List all secrets on the given path

        :param path: Secret path
        :param wrap_ttl: Wrap TTL
        :return: Response

        :raises exceptions.VaultError: On error
        """
        response = await self._list([self._mount_path, path], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)


class BaseSecret(HTTPBase):
    """
    Base secret class, will contain all supported secret backends
    """
    def __init__(self, *args, **kwargs):
        super(BaseSecret, self).__init__(*args, **kwargs)
        self._args = args
        self._kwargs = kwargs

        self._generic = None

    @property
    def generic(self) -> GenericSecretBackend:
        """
        Get the generic secret backend with a default path of "secret"

        :return: Generic secret backend
        """
        if self._generic is None:
            self._generic = GenericSecretBackend(*self._args, **self._kwargs)

        return self._generic

    def get_generic_secret_backend(self, mount_path) -> GenericSecretBackend:
        """
        Get an object representing the generic secret backend on the given mount path

        :param mount_path: Mount path
        :return: Secret backend
        """
        return GenericSecretBackend(*self._args, mount_path=mount_path, **self._kwargs)

    async def list(self, wrap_ttl: Optional[int]=None) -> ResponseBase:
        """
        List secret backends

        :param wrap_ttl: Wrap TTL
        :return: Response
        :raises exceptions.VaultError: On error
        """
        response = await self._get(['sys/mounts'], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)
