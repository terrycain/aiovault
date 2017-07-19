"""
/sys classes
"""
from typing import Union, Optional, List
from .base import HTTPBase, ResponseBase


class BaseSys(HTTPBase):
    """
    Collection of methods to act on the /sys/ URLs
    """
    def __init__(self, *args, **kwargs):
        super(BaseSys, self).__init__(*args, **kwargs)

    async def seal_status(self) -> ResponseBase:
        """
        Get Vault's seal status

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get('sys/seal-status')
        json = await response.json()

        return ResponseBase(json_dict={'data': json}, request_func=self._request)

    async def initialize(self, secret_shares: int=5, secret_threshold: int=3, root_token_pgp_key: Optional[str]=None, pgp_keys: Optional[List[str]]=None) -> ResponseBase:
        """
        Initialize Vault

        :param secret_shares: Number of secret keys
        :param secret_threshold: Number of secret keys to unseal
        :param root_token_pgp_key: Root PGP Key
        :param pgp_keys: PGP Keys
        :return: Response
        """
        payload = {
            'secret_shares': secret_shares,
            'secret_threshold': secret_threshold
        }
        if root_token_pgp_key is not None:
            payload['root_token_pgp_key'] = root_token_pgp_key
        if pgp_keys is not None:
            payload['pgp_keys'] = pgp_keys

        response = await self._put('sys/init', payload=payload)
        json = await response.json()

        return ResponseBase(json_dict={'data': json}, request_func=self._request)

    async def remount(self, path_from: str, path_to: str):
        """
        Remount mounted backend to a different path

        :param path_from: Current mount path
        :param path_to: Destination mount path
        """
        payload = {
            'from': path_from,
            'to': path_to
        }
        await self._post('sys/remount', payload=payload)

    async def unseal(self, key: Optional[str]) -> ResponseBase:
        """
        Unseal Vault

        :param key: Unseal key, if str is None then just resets all unlock operations
        """
        if key is not None:
            payload = {'key': key}
        else:
            payload = {'reset': True}

        response = await self._put('sys/unseal', payload=payload)
        json = await response.json()

        return ResponseBase(json_dict={'data': json}, request_func=self._request)

    async def seal(self):
        """
        Seal Vault
        """
        await self._put('sys/seal')

    async def rotate(self):
        """
        Seal Vault
        """
        await self._put('sys/rotate')

    async def health(self) -> ResponseBase:
        """
        Vault health
        """
        params = {
            'standbyok': 'true',
            'activecode': 200,
            'standbycode': 200,
            'sealedcode': 200,
            'uninitcode': 200
        }

        response = await self._get('sys/health', params=params)
        json = await response.json()

        return ResponseBase(json_dict={'data': json}, request_func=self._request)

