"""
Policy management
"""
from typing import Optional
from .base import HTTPBase, ResponseBase


class BasePolicy(HTTPBase):
    """
    Base policy class
    """
    def __init__(self, *args, **kwargs):
        super(BasePolicy, self).__init__(*args, **kwargs)

    async def create(self, name: str, rules: str):
        """
        Create policy

        :param name: Policy name
        :param rules: Policy HCL as a string
        """
        payload = {
            'rules': rules
        }

        await self._put(['sys/policy', name], payload=payload)

    async def update(self, name: str, rules: str):
        """
        Update policy (technically just overwrites it)

        :param name: Policy name
        :param rules: Policy HCL as a string
        """
        await self.create(name, rules)

    async def delete(self, name: str):
        """
        Delete policy

        :param name: Policy name
        """
        # can delete policy over and over again with a 200 OK
        await self._delete(['sys/policy', name])

    async def read(self, name: str, wrap_ttl: Optional[int]=None) -> ResponseBase:
        """
        Read policy

        :param name: Policy name
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get(['sys/policy', name], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def list(self, wrap_ttl: Optional[int]=None) -> ResponseBase:
        """
        List policies

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get('sys/policy', wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)
