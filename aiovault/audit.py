"""
Vault Audit Backends
"""
from typing import Union, Optional
from .base import HTTPBase, ResponseBase


class FileBackend(HTTPBase):
    async def mount(self, mount_path: str, filepath: str, description: Optional[str]=None, log_raw: bool=False, hmac_accessor: bool=True, mode: int=0o0600, log_format: str='json', line_prefix: Optional[str]=''):
        """
        Mount file audit backend

        :param mount_path: Mount path
        :param filepath: Log file
        :param description: Mount description
        :param log_raw: Log sensitive data without hashing
        :param hmac_accessor: Hash token accessor
        :param mode: Log file mode
        :param log_format: Log format, either json or jsonx
        :param line_prefix: Prefix log line with string
        """
        if log_format not in ('json', 'jsonx'):
            raise ValueError('log_format must be either "json" or "jsonx"')

        payload = {
            'type': 'file',
            'options': {
                'path': filepath,
                'log_raw': str(log_raw).lower(),
                'hmac_accessor': str(hmac_accessor).lower(),
                'mode': '{0:0>4o}'.format(mode),  # oct(0o0600) would generate '0o0600', vault wants 0600
                'format': log_format,
                'prefix': line_prefix

            }
        }
        if description is not None and isinstance(description, str):
            payload['description'] = description

        await self._put(['sys/audit', mount_path], payload=payload)


class SyslogBackend(HTTPBase):
    async def mount(self, mount_path: str, description: Optional[str]=None, log_raw: bool=False, hmac_accessor: bool=True, log_format: str='json', line_prefix: Optional[str]='', facility='AUTH', tag='vault'):
        """
        Mount syslog audit backend

        :param mount_path: Mount path
        :param description: Mount description
        :param log_raw: Log sensitive data without hashing
        :param hmac_accessor: Hash token accessor
        :param log_format: Log format, either json or jsonx
        :param line_prefix: Prefix log line with string
        :param facility: Syslog facility
        :param tag: Syslog tag
        """
        if log_format not in ('json', 'jsonx'):
            raise ValueError('log_format must be either "json" or "jsonx"')

        payload = {
            'type': 'syslog',
            'options': {
                'facility': facility,
                'tag': tag,
                'log_raw': str(log_raw).lower(),
                'hmac_accessor': str(hmac_accessor).lower(),
                'format': log_format,
                'prefix': line_prefix

            }
        }
        if description is not None and isinstance(description, str):
            payload['description'] = description

        await self._put(['sys/audit', mount_path], payload=payload)


class BaseAudit(HTTPBase):
    """
    Base audit module.

    This class is sorta like a placeholder.
    It allows you to mount file backends like

    .. code-block:: python

        with aiovault.VaultClient(token='6c84fb90-12c4-11e1-840d-7b25c5ee775a') as client:
            client.audit.file.mount(...)
            # Or
            client.audit.file.syslog(...)
    """
    def __init__(self, *args, **kwargs):
        super(BaseAudit, self).__init__(*args, **kwargs)
        self._args = args
        self._kwargs = kwargs

        self._file = None
        self._syslog = None

    @property
    def file(self) -> FileBackend:
        """
        Get default file audit backend

        :return: File audit backend
        """
        if self._file is None:
            self._file = FileBackend(*self._args, **self._kwargs)

        return self._file

    @property
    def syslog(self) -> SyslogBackend:
        """
        Get default syslog audit backend

        :return: Syslog audit backend
        """
        if self._syslog is None:
            self._syslog = SyslogBackend(*self._args, **self._kwargs)

        return self._syslog

    async def list(self, wrap_ttl: Union[int, None]=None) -> ResponseBase:
        """
        List audit backends

        :param wrap_ttl: Wrap TTL
        :raises exceptions.VaultError: On error
        """
        response = await self._get('sys/audit', wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def delete(self, path: str) -> ResponseBase:
        """
        Delete an audit backend

        :param path: Audit backend mount path
        :raises exceptions.VaultError: On error
        """
        await self._delete(['sys/audit', path])

    async def hash(self, path: str, input: str, wrap_ttl: Optional[int]=None) -> ResponseBase:
        """
        Get a HMAC of the input based on the given mount path

        .. code-block: python

            with aiovault.VaultClient(token='6c84fb90-12c4-11e1-840d-7b25c5ee775a') as client:
                result = await client.audit.hash('syslog', 'test1')
                print(result['hash'])  # hmac-sha256:SoMeHaShLaLaLaLa


        :param path: Audit backend mount path
        :param input: Input to be hashed
        :param wrap_ttl: Wrap TTL
        :return: A response containing a key 'hash'
        :raises exceptions.VaultError: On error
        """
        payload = {'input': input}
        response = await self._post(['sys/audit-hash', path], payload=payload, wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)
