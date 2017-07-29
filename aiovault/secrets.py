"""
Module containing secret backends
"""
import base64
from typing import Optional, Union, List, Dict
from .base import HTTPBase, ResponseBase


class GenericSecretBackend(HTTPBase):
    """
    The generic secret backend

    By default will use the /secret path, if others exist then call :class:`BaseSecret.get_generic_secret_backend` to get a secret backend object for that path
    """
    def __init__(self, *args, mount_path: str = 'secret', **kwargs):
        super(GenericSecretBackend, self).__init__(*args, **kwargs)

        self._mount_path = mount_path

    async def mount(self, path: str, description: str = '', default_lease_ttl: int = 0, max_lease_ttl: int = 0, force_no_cache: bool = False):
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

    async def read(self, path: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
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

    async def list(self, path: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
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


class TransitSecretBackend(HTTPBase):
    """
    The transit secret backend

    By default will use the /transit path, if others exist then call :class:`BaseSecret.get_transit_secret_backend` to get a secret backend object for that path
    """

    def __init__(self, *args, mount_path: str = 'transit', **kwargs):
        super(TransitSecretBackend, self).__init__(*args, **kwargs)

        self._mount_path = mount_path

    async def mount(self, path: str, description: str = ''):
        """
        Mount the transit secret backend against the path

        :param path: Mount path
        :param description: Mount description

        :raises exceptions.VaultError: On error
        """
        payload = {
            'type': 'transit',
            'description': description,
        }

        await self._post(['sys/mounts', path], payload=payload)

    async def create(self, name: str, convergent_encryption: bool = False, derived: bool = False, exportable: bool = False, key_type: str = 'aes256-gcm96'):
        """
        Create a key

        :param name: Key Name
        :param convergent_encryption: If true then same plaintext creates the same ciphertext
        :param derived: Key derivation
        :param exportable: If the raw key is exportable
        :param key_type: Key type, one of aes256-gcm96, ecdsa-p256 or ed25519

        :raises exceptions.VaultError: On error
        :raises ValueError: When an unsupported keytype is given
        """
        if key_type not in ('aes256-gcm96', 'ecdsa-p256', 'ed25519'):
            raise ValueError("Key type not supported")

        payload = {
            'convergent_encryption': convergent_encryption,
            'derived': derived,
            'exportable': exportable,
            'type': key_type
        }
        await self._post([self._mount_path, 'keys', name], payload=payload)

    async def read(self, name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Read transit key

        :param name: Key name
        :param wrap_ttl: Wrap TTL
        :return: Response

        :raises exceptions.VaultError: On error
        """
        response = await self._get([self._mount_path, 'keys', name], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def list(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List transit key

        :param wrap_ttl: Wrap TTL
        :return: Response

        :raises exceptions.VaultError: On error
        """
        response = await self._list([self._mount_path, 'keys'], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def delete(self, name: str):
        """
        Delete transit key

        :param name: Key name

        :raises exceptions.VaultError: On error
        """
        await self._delete([self._mount_path, 'keys', name])

    async def update(self, name: str, min_decryption_version: int = 0, min_encryption_verison: int = 0, deletion_allowed: bool = False):
        """
        Update the transit key

        :param name: Key name
        :param min_decryption_version: Minimum version of ciphertext allowed to be decrypted
        :param min_encryption_verison: Minimum version of plaintext allowed to be encrypted
        :param deletion_allowed: Allow key to be deleted

        :raises exceptions.VaultError: On error
        """
        payload = {
            'min_decryption_version': min_decryption_version,
            'min_encryption_verison': min_encryption_verison,
            'deletion_allowed': deletion_allowed
        }
        await self._post([self._mount_path, 'keys', name, 'config'], payload=payload)

    async def rotate(self, name: str):
        """
        Rotate transit key

        :param name: Key name

        :raises exceptions.VaultError: On error
        """
        await self._post([self._mount_path, 'keys', name, 'rotate'])

    async def export(self, name: str, key_type: str, version: str = 'latest') -> ResponseBase:
        """
        Export transit key

        :param name: Key name
        :param key_type: Type of key to export, can be encryption-key, signing-key or hmac-key
        :param version: Specifies key version to export or get the latest one

        :raises exceptions.VaultError: On error
        :raises ValueError: When key_type is invalid
        """
        if key_type not in ('encryption-key', 'signing-key', 'hmac-key'):
            raise ValueError('Key type is invalid')

        response = await self._get([self._mount_path, 'export', key_type, name, version])
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def encrypt(self, name: str, plaintext: Union[str, bytes], context: Union[str, bytes] = '', key_version: Optional[int] = None, nonce: Union[str, bytes] = '',
                      batch_input: Optional[List[Dict[str, Union[str, bytes]]]] = None, key_type: str = 'aes256-gcm96', convergent_encryption: Optional[str] = None) -> ResponseBase:
        """
        Encrypt plaintext

        :param name: Key name
        :param plaintext: Plaintext bytes or string (it will end up base64 encoded)
        :param context: Key derivation context (it will be base64 encoded)
        :param key_version: If not provided latest is given (it will be base64 encoded)
        :param nonce: nonce value, needed for convergent encryption (it will be base64 encoded)
        :param batch_input: A list of bytes or string
        :param key_type: Key type
        :param convergent_encryption:

        :raises exceptions.VaultError: On error
        :raises ValueError: When key_type is invalid
        """
        # pylint: disable=too-many-branches
        if key_type not in ('aes256-gcm96', 'ecdsa-p256', 'ed25519'):
            raise ValueError("Key type not supported")

        payload = {}
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        payload['plaintext'] = base64.b64encode(plaintext).decode()
        if context:
            if isinstance(context, str):
                context = context.encode()
            payload['context'] = base64.b64encode(context).decode()

        if key_version is not None:
            payload['key_version'] = key_version

        if nonce:
            if isinstance(nonce, str):
                nonce = nonce.encode()
            payload['nonce'] = base64.b64encode(nonce).decode()

        if batch_input is not None:
            payload['batch_input'] = []
            for obj in batch_input:
                item = {}

                if 'context' in obj:
                    if isinstance(obj['context'], str):
                        item['context'] = base64.b64encode(obj['context'].encode()).decode()
                    else:
                        item['context'] = base64.b64encode(obj['context']).decode()

                if isinstance(obj['plaintext'], str):
                    item['plaintext'] = base64.b64encode(obj['plaintext'].encode()).decode()
                else:
                    item['plaintext'] = base64.b64encode(obj['plaintext']).decode()

                payload['batch_input'].append(item)

        payload['type'] = key_type

        if convergent_encryption is not None:
            payload['convergent_encryption'] = convergent_encryption

        response = await self._post([self._mount_path, 'encrypt', name], payload=payload)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def decrypt(self, name: str, ciphertext: Union[str, bytes], context: Union[str, bytes] = '', nonce: Union[str, bytes] = '',
                      batch_input: Optional[List[Dict[str, Union[str, bytes]]]] = None) -> ResponseBase:

        """
        Decrypt ciphertext

        :param name: Key name
        :param ciphertext: Ciphertext (it will be base64 encoded if ciphertext is bytes)
        :param context: Key derivation context (it will be base64 encoded if context is bytes)
        :param nonce: nonce value, needed for convergent encryption (it will be base64 encoded if nonce is bytes)
        :param batch_input: A list of bytes or string

        :raises exceptions.VaultError: On error
        :raises ValueError: When key_type is invalid
        """
        # pylint: disable=too-many-branches
        payload = {}
        if isinstance(ciphertext, bytes):
            ciphertext = base64.b64encode(ciphertext).decode()

        payload['ciphertext'] = ciphertext
        if context:
            if isinstance(context, bytes):
                context = base64.b64encode(context).decode()
            payload['context'] = context

        if nonce:
            if isinstance(nonce, bytes):
                nonce = base64.b64encode(nonce).decode()
            payload['nonce'] = nonce

        if batch_input is not None:
            payload['batch_input'] = []
            for obj in batch_input:
                item = {}

                if 'context' in obj:
                    if isinstance(obj['context'], bytes):
                        item['context'] = base64.b64encode(obj['context']).decode()
                    else:
                        item['context'] = obj['context']

                if 'nonce' in obj:
                    if isinstance(obj['nonce'], bytes):
                        item['nonce'] = base64.b64encode(obj['nonce']).decode()
                    else:
                        item['nonce'] = obj['nonce']

                if isinstance(obj['ciphertext'], bytes):
                    item['ciphertext'] = base64.b64encode(obj['ciphertext']).decode()
                else:
                    item['ciphertext'] = obj['ciphertext']

                payload['batch_input'].append(item)

        response = await self._post([self._mount_path, 'decrypt', name], payload=payload)
        json = await response.json()

        if 'plaintext' in json['data']:
            result = base64.b64decode(json['data']['plaintext'].encode())

            try:
                json['data']['plaintext'] = result.decode()
            except ValueError:
                json['data']['plaintext'] = result

        if 'batch_results' in json['data']:
            result = []

            for item in json['data']['batch_results']:
                plaintext = base64.b64decode(item['plaintext'].encode())

                try:
                    result.append({'plaintext': plaintext.decode()})
                except ValueError:
                    result.append({'plaintext': plaintext})

            json['data']['batch_results'] = result

        return ResponseBase(json_dict=json, request_func=self._request)

    async def rewrap(self, name: str, ciphertext: str, context: str = '', nonce: str = '', key_version: Optional[int] = None,
                     batch_input: Optional[List[Dict[str, Union[str, bytes]]]] = None) -> ResponseBase:
        """
        Rewrap ciphertext

        :param name: Key name
        :param ciphertext: Ciphertext, must be the vault string
        :param context: Key derivation context
        :param key_version: Key Version, latest if None
        :param nonce: nonce value, needed for convergent encryption
        :param batch_input: Result from vault

        :raises exceptions.VaultError: On error

        :raises exceptions.VaultError: On error
        :raises ValueError: When key_type is invalid
        """
        payload = {
            'ciphertext': ciphertext
        }
        if context:
            payload['context'] = context

        if nonce:
            payload['nonce'] = nonce

        if key_version is not None:
            payload['key_version'] = key_version

        if batch_input is not None:
            payload['batch_input'] = batch_input

        response = await self._post([self._mount_path, 'rewrap', name], payload=payload)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def generate_key_data(self, name: str, context: Union[str, bytes] = '', nonce: Union[str, bytes] = '',
                                result_type: str = 'wrapped', bits: int = 512) -> ResponseBase:
        """
        Generate key and encrypt it with the named key

        :param name: Key name
        :param context: Key derivation context (it will be base64 encoded)
        :param nonce: nonce value, needed for convergent encryption (it will be base64 encoded)
        :param result_type: Key type either ciphertext or plaintext
        :param bits: Number of bits either 128, 256, 512

        :raises exceptions.VaultError: On error
        :raises ValueError: When key_type or bits is invalid
        """
        if result_type not in ('wrapped', 'plaintext'):
            raise ValueError("Result type not supported")
        if bits not in (128, 258, 512):
            raise ValueError("Number of bits not supported")

        payload = {
            'bits': bits
        }
        if context:
            if isinstance(context, str):
                context = context.encode()
            payload['context'] = base64.b64encode(context).decode()

        if nonce:
            if isinstance(nonce, str):
                nonce = nonce.encode()
            payload['nonce'] = base64.b64encode(nonce).decode()

        response = await self._post([self._mount_path, 'datakey', result_type, name], payload=payload)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def generate_random_bytes(self, length: int = 32, result_format: str = 'bytes') -> ResponseBase:
        """
        Generate random bytes

        :param length: Length of random data
        :param result_format: Byte format

        :raises exceptions.VaultError: On error
        :raises ValueError: When key_type or bits is invalid
        """
        if result_format not in ('bytes', 'base64', 'hex'):
            raise ValueError("Format type not supported")

        payload = {
            'bytes': length,
            'format': result_format if result_format != 'bytes' else 'base64'
        }

        response = await self._post([self._mount_path, 'random'], payload=payload)
        json = await response.json()

        if result_format == 'bytes':
            json['data']['random_bytes'] = base64.b64decode(json['data']['random_bytes'].encode())

        return ResponseBase(json_dict=json, request_func=self._request)

    # Not coding /transit/hash as can do that in python

    async def generate_hmac(self, name: str, input_string: Union[str, bytes], key_version: Optional[int] = None, algorithm: str = 'sha2-256', result_format: str = 'base64') -> ResponseBase:
        """
        Generate HMAC

        :param name: Key name
        :param input_string: Data to be hmac'd (it will be base64 encoded)
        :param key_version: Key version, if None the latest is picked
        :param algorithm: Algorithm to use sha2-224, sha2-256, sha2-384, sha2-512
        :param result_format: Byte format

        :raises exceptions.VaultError: On error
        :raises ValueError: When key_type or bits is invalid
        """
        if isinstance(input_string, str):
            input_string = input_string.encode()
        input_string = base64.b64encode(input_string).decode()

        if result_format not in ('base64', 'hex'):
            raise ValueError("Format type not supported")

        if algorithm not in ('sha2-224', 'sha2-256', 'sha2-384', 'sha2-512'):
            raise ValueError("Format type not supported")

        payload = {
            'input': input_string,
            'algorithm': algorithm,
            'format': result_format
        }
        if key_version is not None:
            payload['key_version'] = key_version

        response = await self._post([self._mount_path, 'hmac', name], payload=payload)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def sign(self, name: str, input_string: Union[str, bytes], key_version: Optional[int] = None, algorithm: str = 'sha2-256') -> ResponseBase:
        """
        Sign data

        :param name: Key name
        :param input_string: Data to be hmac'd (it will be base64 encoded)
        :param key_version: Key version, if None the latest is picked
        :param algorithm: Algorithm to use sha2-224, sha2-256, sha2-384, sha2-512

        :raises exceptions.VaultError: On error
        :raises ValueError: When key_type or bits is invalid
        """
        if algorithm not in ('sha2-224', 'sha2-256', 'sha2-384', 'sha2-512'):
            raise ValueError("Format type not supported")

        if isinstance(input_string, str):
            input_string = input_string.encode()
        input_string = base64.b64encode(input_string).decode()

        payload = {
            'input': input_string,
            'algorithm': algorithm,
        }
        if key_version is not None:
            payload['key_version'] = key_version

        response = await self._post([self._mount_path, 'sign', name], payload=payload)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def verify(self, name: str, input_string: Union[str, bytes], signature: Optional[str] = None, hmac: Optional[str] = None,
                     algorithm: str = 'sha2-256', result_format: str = 'base64') -> ResponseBase:
        """
        Verify data

        Either HMAC or signature must be provided

        :param name: Key name
        :param input_string: Data to be hmac'd (it will be base64 encoded)
        :param signature: /transit/sign signature
        :param hmac: HMAC
        :param result_format: Result format
        :param algorithm: Algorithm to use sha2-224, sha2-256, sha2-384, sha2-512

        :raises exceptions.VaultError: On error
        :raises ValueError: When key_type or bits is invalid
        """
        if signature is None and hmac is None:
            raise ValueError("Signature or HMAC must be provided")

        if algorithm not in ('sha2-224', 'sha2-256', 'sha2-384', 'sha2-512'):
            raise ValueError("Format type not supported")

        if result_format not in ('base64', 'hex'):
            raise ValueError("Format type not supported")

        if isinstance(input_string, str):
            input_string = input_string.encode()
        input_string = base64.b64encode(input_string).decode()

        payload = {
            'input': input_string,
            'algorithm': algorithm,
            'format': result_format
        }
        if signature is not None:
            payload['signature'] = signature
        else:
            payload['hmac'] = hmac

        response = await self._post([self._mount_path, 'verify', name], payload=payload)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)


class TOTPSecretBackend(HTTPBase):
    """
    The time based one-time-password secret backend

    By default will use the /totp path, if others exist then call :class:`BaseSecret.get_totp_secret_backend` to get a TOTP backend object for that path
    """
    def __init__(self, *args, mount_path: str = 'totp', **kwargs):
        super(TOTPSecretBackend, self).__init__(*args, **kwargs)

        self._mount_path = mount_path

    async def mount(self, path: str, description: str = ''):
        """
        Mount the TOTP secret backend against the path

        :param path: Mount path
        :param description: Mount description

        :raises exceptions.VaultError: On error
        """
        payload = {
            'type': 'totp',
            'description': description,
        }

        await self._post(['sys/mounts', path], payload=payload)

    async def create(self, name: str, generate: bool = False, exported: bool = True, key_size: int = 20, url: str = '', issuer: str = '',
                     account_name: str = '', period: int = 30, algorithm: str = 'SHA1', digits: int = 6, skew: int = 1, qr_size: int = 200,
                     wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Create or update TOTP Key definition

        :param name: Key name
        :param generate: Key is generated by Vault
        :param exported: Specifies if QR code and URL should be returned, only used if generate is True
        :param key_size: Size in bytes the key will be
        :param url: URL that can be used to configure the key
        :param issuer: Issuer name (required if generate is true)
        :param account_name: Account name (required if generate is true)
        :param period: Token period
        :param algorithm: Key algorithm, one of ("SHA1", "SHA256", "SHA512")
        :param digits: Key digits, one of (6, 8)
        :param skew: Time periods either side of now that will be allowed when validating, one of (0, 1)
        :param qr_size: QR size in pixels
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        if algorithm not in ('SHA1', 'SHA256', 'SHA512'):
            raise ValueError("Algorithm not SHA1, SHA256 or SHA512")
        if digits not in (6, 8):
            raise ValueError("Digits must be either 6 or 8")
        if skew not in (0, 1):
            raise ValueError("Skew must be either 0 or 1")

        payload = {
            'generate': generate,
            'exported': exported,
            'key_size': key_size,
            'url': url,
            'issuer': issuer,
            'account_name': account_name,
            'period': period,
            'algorithm': algorithm,
            'digits': digits,
            'skew': skew,
            'qr_size': qr_size
        }

        response = await self._post([self._mount_path, 'keys', name], payload=payload, wrap_ttl=wrap_ttl)
        if response.status == 204:  # Can produce no output if no QR code, but this keeps the return valueconstant
            return ResponseBase(json_dict={}, request_func=self._request)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def read(self, name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Read TOTP Key configuration

        :param name: Key name
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get([self._mount_path, 'keys', name], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def list(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List TOTP keys

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list([self._mount_path, 'keys'], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def delete(self, name: str):
        """
        Delete TOTP key

        :param name: Key name
        :return: Response
        """
        await self._delete([self._mount_path, 'keys', name])

    async def generate_code(self, name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Generate TOTP code

        :param name:
        :param wrap_ttl:

        :return: Response
        """
        response = await self._get([self._mount_path, 'code', name], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def validate_code(self, name: str, code: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Validate TOTP code

        :param name: Key name
        :param code: TOTP code
        :param wrap_ttl: Wrap TTL

        :return: Response
        """
        payload = {'code': code}

        response = await self._post([self._mount_path, 'code', name], payload=payload, wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)


class ConsulSecretBackend(HTTPBase):
    """
    Consul secret backend
    """
    def __init__(self, *args, mount_path: str = 'consul', **kwargs):
        super(ConsulSecretBackend, self).__init__(*args, **kwargs)

        self._mount_path = mount_path

    async def mount(self, path: str, address: str, port: int, management_token: str, https: bool = True, description: str = ''):
        """
        Mount the consul secret backend against the path

        :param path: Mount path
        :param address: Consul address
        :param port: Consul port
        :param management_token: A consul management token
        :param https: Consul port is HTTPS
        :param description: Mount description

        :raises exceptions.VaultError: On error
        """
        payload = {
            'type': 'consul',
            'description': description,
        }
        payload2 = {
            'address': '{0}:{1}'.format(address, port),
            'scheme': 'https' if https else 'http',
            'token': management_token
        }

        await self._post(['sys/mounts', path], payload=payload)
        await self._post([path, 'config/access'], payload=payload2)

    async def create(self, name: str, consul_policy: Optional[Union[str, bytes]] = None, lease: str = '', token_type: str = 'client'):
        """
        Create a consul role

        :param name: Role name
        :param consul_policy: Consul policy (will be base64 encoded regardless)
        :param lease: Lease, should be a go time string like 54s or 1h 5s
        :param token_type: Either client or management
        """
        if token_type not in ('client', 'management'):
            raise ValueError("token_type must be either client or management")

        if token_type == 'client' and consul_policy is None:
            raise ValueError('Must supply a policy when token type is client')

        if isinstance(consul_policy, str):
            consul_policy = consul_policy.encode()
        consul_policy = base64.b64encode(consul_policy).decode()

        payload = {
            'lease': lease,
            'policy': consul_policy,
            'token_type': token_type,
        }

        await self._post([self._mount_path, 'roles', name], payload=payload)

    async def read(self, name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Read consul role

        :param name: Role name
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get([self._mount_path, 'roles', name], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def list(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List consul roles

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list([self._mount_path, 'roles'], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def delete(self, name: str):
        """
        Delete role

        :param name: Role name
        """
        await self._delete([self._mount_path, 'roles', name])

    async def generate_credential(self, name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Generate consul credentials for a given role

        :param name: Role name
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get([self._mount_path, 'creds', name], wrap_ttl=wrap_ttl)
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
        self._transit = None
        self._totp = None
        self._consul = None

    @property
    def generic(self) -> GenericSecretBackend:
        """
        Get the generic secret backend with a default path of "secret"

        :return: Generic secret backend
        """
        if self._generic is None:
            self._generic = GenericSecretBackend(*self._args, **self._kwargs)

        return self._generic

    @property
    def transit(self) -> TransitSecretBackend:
        """
        Get the transit secret backend with a default path of "transit"

        :return: Transit secret backend
        """
        if self._transit is None:
            self._transit = TransitSecretBackend(*self._args, **self._kwargs)

        return self._transit

    @property
    def totp(self) -> TOTPSecretBackend:
        """
        Get the TOTP secret backend with a default path of "totp"

        :return: TOTP secret backend
        """
        if self._totp is None:
            self._totp = TOTPSecretBackend(*self._args, **self._kwargs)

        return self._totp

    @property
    def consul(self) -> ConsulSecretBackend:
        """
        Get the consul secret backend with a default path of "consul"

        :return: Consul secret backend
        """
        if self._consul is None:
            self._consul = ConsulSecretBackend(*self._args, **self._kwargs)

        return self._consul

    def get_generic_secret_backend(self, mount_path) -> GenericSecretBackend:
        """
        Get an object representing the generic secret backend on the given mount path

        :param mount_path: Mount path
        :return: Secret backend
        """
        return GenericSecretBackend(*self._args, mount_path=mount_path, **self._kwargs)

    def get_transit_secret_backend(self, mount_path) -> TransitSecretBackend:
        """
        Get an object representing the transit secret backend on the given mount path

        :param mount_path: Mount path
        :return: Transit backend
        """
        return TransitSecretBackend(*self._args, mount_path=mount_path, **self._kwargs)

    def get_totp_secret_backend(self, mount_path) -> TOTPSecretBackend:
        """
        Get an object representing the TOTP secret backend on the given mount path

        :param mount_path: Mount path
        :return: TOTP backend
        """
        return TOTPSecretBackend(*self._args, mount_path=mount_path, **self._kwargs)

    def get_consul_secret_backend(self, mount_path) -> ConsulSecretBackend:
        """
        Get an object representing the consul secret backend on the given mount path

        :param mount_path: Mount path
        :return: Consul backend
        """
        return ConsulSecretBackend(*self._args, mount_path=mount_path, **self._kwargs)

    async def list(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List secret backends

        :param wrap_ttl: Wrap TTL
        :return: Response
        :raises exceptions.VaultError: On error
        """
        response = await self._get(['sys/mounts'], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)
