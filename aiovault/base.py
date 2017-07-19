"""
Base classes
"""
from typing import Optional, Union, List, Awaitable, Callable

from collections import Mapping
import datetime
import dateutil.parser
import dateutil.relativedelta
import asyncio

import aiohttp
import aiohttp.client

from . import exceptions

VAUTL_URL = 'http://localhost:8200'


class HTTPBase(object):
    """
    A generic HTTP class which provides various _get, _list _post etc... methods to query vault
    """
    def __init__(self,
                 vault_url: str = VAUTL_URL,
                 token: Optional[str]=None,
                 verify: bool = True,
                 timeout: int = 10,
                 session: Optional[aiohttp.ClientSession] = None,
                 loop: asyncio.AbstractEventLoop = None
                 ) -> None:

        self.loop = loop
        if loop is None:
            self.loop = asyncio.get_event_loop()

        self.vault_url = vault_url.rstrip('/')

        self.session = session
        if session is None:
            if not verify:
                connector = aiohttp.TCPConnector(verify_ssl=False, loop=self.loop)
            else:
                connector = None

            self.session = aiohttp.ClientSession(connector=connector, read_timeout=timeout, conn_timeout=timeout, loop=self.loop)

        self._auth_token = token
        self.timeout = timeout

    def __del__(self):
        self.close()

    def close(self):
        """
        Close aiohttp session
        """
        if not self.session.closed:
            self.session.close()

    def _make_url(self, path: Union[str, List[str]]) -> str:
        """
        Create a full url to vault

        will join a http prefix like http://vault:5200 with /v1/ and a string or list of paths
        e.g.

        a path of ['auth/user', 'test'] will become http://vault:5200/v1/auth/user/test

        :param path: Vault URL components
        :return: Full vault URL
        """
        if isinstance(path, str):
            return '{0}/v1/{1}'.format(self.vault_url, path.lstrip('/'))
        elif isinstance(path, list):
            return '{0}/v1/{1}'.format(self.vault_url, '/'.join([item.strip('/') for item in path]))
        else:
            raise ValueError("Path isnt a str or list of str")

    async def _get(self, path: Union[str, List[str]], params: Optional[dict]=None, wrap_ttl: Optional[int]=None) -> Awaitable[aiohttp.client.ClientResponse]:
        """
        HTTP GET request

        :param path: Path components
        :param wrap_ttl: Optional TTL
        :return: A response object from aiohttp
        """
        return await self._request('get', path, payload=None, params=params, wrap_ttl=wrap_ttl)

    async def _delete(self, path: Union[str, List[str]], params: Optional[dict]=None, wrap_ttl: Optional[int]=None) -> Awaitable[aiohttp.client.ClientResponse]:
        """
        HTTP DELETE request

        :param path: Path components
        :param wrap_ttl: Optional TTL
        :return: A response object from aiohttp
        """
        return await self._request('delete', path, payload=None, params=params, wrap_ttl=wrap_ttl)

    async def _list(self, path: Union[str, List[str]], params: Optional[dict]=None, wrap_ttl: Optional[int]=None) -> Awaitable[aiohttp.client.ClientResponse]:
        """
        HTTP LIST request

        :param path: Path components
        :param wrap_ttl: Optional TTL
        :return: A response object from aiohttp
        """
        return await self._request('list', path, payload=None, params=params, wrap_ttl=wrap_ttl)

    async def _post(self, path: Union[str, List[str]], payload: Optional[dict]=None, params: Optional[dict]=None, wrap_ttl: Optional[int]=None) -> Awaitable[aiohttp.client.ClientResponse]:
        """
        HTTP POST request

        :param path: Path components
        :param payload: Dictonary of key value to be turned into JSON
        :param wrap_ttl: Optional TTL
        :return: A response object from aiohttp
        """
        return await self._request('post', path, payload=payload, params=params, wrap_ttl=wrap_ttl)

    async def _put(self, path: Union[str, List[str]], payload: Optional[dict]=None, params: Optional[dict]=None, wrap_ttl: Optional[int]=None) -> Awaitable[aiohttp.client.ClientResponse]:
        """
        HTTP PUT request

        :param path: Path components
        :param payload: Dictonary of key value to be turned into JSON
        :param wrap_ttl: Optional TTL
        :return: A response object from aiohttp
        """
        return await self._request('put', path, payload=payload, params=params, wrap_ttl=wrap_ttl)

    async def _request(self, method: str, path: Union[str, List[str]], payload: Optional[dict], params: Optional[dict]=None, wrap_ttl: Optional[int]=None) -> Awaitable[aiohttp.client.ClientResponse]:
        """
        HTTP Request method which takes a method

        It will take care of getting aiohttp to use a HTTP LIST verb

        Adds in the Token and TTL headers, also converts payloads to JSON

        :param method: HTTP Method
        :param path: Path components
        :param payload: Dictonary of key value to be turned into JSON
        :param params: Querystring parameters
        :param wrap_ttl: Optional TTL
        :return: A response object from aiohttp
        """
        url = self._make_url(path)

        headers = {}

        if self._auth_token is not None:
            headers['X-Vault-Token'] = self._auth_token
        if wrap_ttl is not None:
            headers['X-Vault-Wrap-TTL'] = str(wrap_ttl)

        kwargs = {'headers': headers}
        if payload is not None:
            kwargs['json'] = payload

        if params is not None:
            kwargs['params'] = params

        async with aiohttp.ClientSession(loop=self.loop) as session:
            if method != 'list':
                method_func = getattr(session, method)(url, **kwargs)
            else:
                method_func = aiohttp.client._RequestContextManager(session._request('LIST', url, **kwargs))

            async with method_func as response:
                return await self._validate_response(response)

    @classmethod
    async def _validate_response(cls, response: aiohttp.client.ClientResponse) -> Awaitable[aiohttp.client.ClientResponse]:
        """
        Takes in a HTTP response, looks through it to see if its legit, if not raise some errors.
        If all is good return the response

        :param response: aiohttp response
        :return: aiohttp response
        """
        if 400 <= response.status < 600:
            if response.headers.get('Content-Type') == 'application/json':
                json_data = await response.json()
                cls._raise_error(response.status, errors=json_data.get('errors'))
            else:
                text = await response.text()
                cls._raise_error(response.status, message=text)
        else:
            return response

    @staticmethod
    def _raise_error(status: int, message: Optional[str]=None, errors: Optional[list]=None):
        """
        Raise an error based on the status code

        :param status: HTTP response status
        :param message: JSON message
        :param errors: JSON error
        :raises exceptions.InvalidRequest: On HTTP 400
        :raises exceptions.Unauthorized: On HTTP 401
        :raises exceptions.Forbidden: On HTTP 403
        :raises exceptions.InvalidPath: On HTTP 404
        :raises exceptions.RateLimitExceeded: On HTTP 429
        :raises exceptions.InternalServerError: On HTTP 500
        :raises exceptions.VaultNotInitialized: On HTTP 501
        :raises exceptions.VaultDown: On HTTP 503
        :raises exceptions.UnexpectedError: On any other HTTP response
        """
        if status == 400:
            raise exceptions.InvalidRequest(message, errors=errors)
        elif status == 401:
            raise exceptions.Unauthorized(message, errors=errors)
        elif status == 403:
            raise exceptions.Forbidden(message, errors=errors)
        elif status == 404:
            raise exceptions.InvalidPath(message, errors=errors)
        elif status == 429:
            raise exceptions.RateLimitExceeded(message, errors=errors)
        elif status == 500:
            raise exceptions.InternalServerError(message, errors=errors)
        elif status == 501:
            raise exceptions.VaultNotInitialized(message, errors=errors)
        elif status == 503:
            raise exceptions.VaultDown(message, errors=errors)
        else:
            raise exceptions.UnexpectedError(message)


class ResponseBase(Mapping):
    """
    A class which wraps the JSON response from Vault

    As it stands the class also implements a read only dictionary type data structure which will
    base its keys of any content inside the 'data' portion of a Vault response. Am undecided yet if
    I want to optionally change that base to 'auth' when thats populated.

    It can also unwrap wrapped responses and rewrap responses, has convenience methods to check expiry etc...
    """
    def __init__(self, json_dict: dict, request_func: Callable[[str, Union[str, List[str]], Optional[dict], Optional[int]], Awaitable[aiohttp.client.ClientResponse]]) -> None:
        self._request = request_func

        self.warnings = None
        self.auth = None
        self.renewable = None
        self.lease_duration = None
        self.data = None
        self.wrap_info = None

        self.lease_id = None
        self.request_id = None

        self.wrapped_at = None
        self.expires_at = None

        self._set(json_dict)

    def _set(self, json_dict: dict):
        """
        Sets instance variables to values from a Vault JSON payload

        :param json_dict: JSON dictionary
        """
        self.warnings = json_dict.get('warnings', None)
        self.auth = json_dict.get('auth', None)
        self.renewable = json_dict.get('renewable')
        self.lease_duration = json_dict.get('lease_duration', 0)
        self.data = json_dict.get('data', None)
        self.wrap_info = json_dict.get('wrap_info', None)

        lease_id = json_dict.get('lease_id', '')
        request_id = json_dict.get('request_id', '')
        self.lease_id = lease_id if lease_id != '' else None
        self.request_id = request_id if request_id != '' else None

        if self.data is None:
            self.data = {}

        if self.is_wrapped:
            self.wrapped_at = dateutil.parser.parse(self.wrap_info['creation_time'])
            self.expires_at = self.wrapped_at + dateutil.relativedelta.relativedelta(seconds=self.wrap_info['ttl'])

    @property
    def is_wrapped(self) -> bool:
        """
        Determine if the response is wrapped
        :return: True if the response is wrapped
        """
        return self.wrap_info is not None

    @property
    def wrap_expired(self) -> bool:
        """
        Check if a wrapped response has expired, if the response is not wrapped, it will always return True

        :return: True if the wrapped response has expired
        """
        if self.is_wrapped:
            return datetime.datetime.now(tz=self.wrapped_at.tzinfo) > self.expires_at
        else:
            return True

    async def unwrap(self, wrap_ttl: Optional[int]=None):
        """
        Unwrap a wrapped respone else do nothing

        :param wrap_ttl: Wrap TTL
        """
        if self.is_wrapped:
            if self.wrap_expired:
                raise exceptions.VaultWrapExpired()
            payload = {'token': self.wrap_info['token']}
            response = await self._request('post', 'sys/wrapping/unwrap', payload, wrap_ttl=wrap_ttl)
            json_dict = await response.json()

            self._set(json_dict)

    async def rewrap(self):
        """
        Rewrap a wrapped response
        """
        if self.is_wrapped:
            if self.wrap_expired:
                raise exceptions.VaultWrapExpired()
            payload = {'token': self.wrap_info['token']}
            response = await self._request('post', 'sys/wrapping/rewrap', payload)
            json_dict = await response.json()

            self._set(json_dict)

    def __getitem__(self, item):
        return self.data.__getitem__(item)

    def __iter__(self):
        return self.data.__iter__()

    def __len__(self):
        return self.data.__len__()
