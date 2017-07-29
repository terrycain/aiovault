"""
Authentication backend
"""
import json
from typing import Optional, List, Dict

from .base import HTTPBase, ResponseBase
from .exceptions import InvalidPath, InternalServerError


class LDAPAuthBackend(HTTPBase):
    """
    Vault LDAP authentication backend
    """
    def __init__(self, *args, mount_path: str = 'ldap', **kwargs) -> None:
        super(LDAPAuthBackend, self).__init__(*args, **kwargs)

        self.mount_path = 'auth/' + mount_path

    async def mount(self, mount_path: str,
                    url: str, binddn: str = '', bindpass: str = '', userdn: str = '', userattr: str = 'uid', discoverdn: bool = False, deny_null_bind: bool = True, upndomain: str = '',
                    groupfilter: str = '(|(memberUid={{.Username}})(member={{.UserDN}})(uniqueMember={{.UserDN}}))', groupdn: str = '', groupattr: str = 'cn',
                    description: str = '', starttls: bool = False, tls_min_version: str = 'tls12', tls_max_version: str = 'tls12', insecure_tls: bool = False, certificate: str = ''):
        """
        Mount an LDAP backend

        :param mount_path: Mount path
        :param url: LDAP URL
        :param binddn: Bind DN
        :param bindpass: Bind password
        :param userdn: User DN
        :param userattr: User attribute
        :param discoverdn: If true use an anonymous bind to find user DN
        :param deny_null_bind: Deny empty passwords
        :param upndomain: userPrincipalDomain for Active Directory
        :param groupfilter: Group filter
        :param groupdn: Group DN
        :param groupattr: Group attribute
        :param description: Mount description
        :param starttls: Use StartTLS
        :param tls_min_version: TLS minimum version
        :param tls_max_version: TLS maximum version
        :param insecure_tls: Skip SSL cert verification
        :param certificate: CA certificate
        """
        # pylint: disable=too-many-arguments,too-many-locals
        payload = {
            'type': 'ldap',
            'description': description,
        }

        payload2 = {
            'url': url,
            'binddn': binddn,
            'bindpass': bindpass,
            'userdn': userdn,
            'userattr': userattr,
            'discoverdn': discoverdn,
            'deny_null_bind': deny_null_bind,
            'upndomain': upndomain,

            'groupfilter': groupfilter,
            'groupdn': groupdn,
            'groupattr': groupattr,

            'starttls': starttls,
            'tls_min_version': tls_min_version,
            'tls_max_version': tls_max_version,
            'insecure_tls': insecure_tls,
            'certificate': certificate
        }

        await self._post(['sys/auth', mount_path], payload=payload)
        await self._post(['auth', mount_path, 'config'], payload=payload2)

    async def get_config(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Get LDAP config
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get([self.mount_path, 'config'], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def list_groups(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List LDAP groups

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list([self.mount_path, 'groups'], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def create_group(self, name: str, policies: List[str]):
        """
        Create group (groups are local to vault but will be matched to groups coming from LDAP)

        :param name: Group name
        :param policies: Policies
        """
        payload = {'policies': ','.join(policies)}
        await self._post([self.mount_path, 'groups', name], payload=payload)

    async def read_group(self, name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Read group info

        :param name: Group name
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get([self.mount_path, 'groups', name], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def delete_group(self, name: str):
        """
        Delete group

        :param name: Group name
        """
        await self._delete([self.mount_path, 'groups', name])

    async def list_users(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List users

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list([self.mount_path, 'users'], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def create_user(self, name: str, policies: List[str]):
        """
        Create user
        :param name: Username
        :param policies: policies
        """
        payload = {'policies': ','.join(policies)}
        await self._post([self.mount_path, 'users', name], payload=payload)

    async def read_user(self, name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Read user config

        :param name: Username
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get([self.mount_path, 'users', name], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def delete_user(self, name: str):
        """
        Delete user

        :param name: Username
        """
        await self._delete([self.mount_path, 'users', name])

    async def login(self, username: str, password: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Authorise against LDAP

        :param username: Username
        :param password: Password
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._post([self.mount_path, 'login', username], payload={'password': password}, wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)


class GitHubAuthBackend(HTTPBase):
    """
    Vault GitHub authentication backend
    """
    def __init__(self, *args, mount_path: str = 'github', **kwargs) -> None:
        super(GitHubAuthBackend, self).__init__(*args, **kwargs)

        self.mount_path = 'auth/' + mount_path

    async def mount(self, mount_path: str, organization: str, description: str = '', base_url: Optional[str] = None, ttl: Optional[str] = None, max_ttl: Optional[str] = None):
        """
        Mount the GitHub backend againt the given path

        :param mount_path: Mount path
        :param organization: GitHub Organisation
        :param description: Description
        :param base_url: Base URL
        :param ttl: TTL
        :param max_ttl: Max TTL
        """
        payload = {
            'type': 'github',
            'description': description,
        }

        payload2 = {
            'organization': organization
        }
        if base_url is not None:
            payload2['base_url'] = base_url
        if ttl is not None:
            payload2['ttl'] = ttl
        if max_ttl is not None:
            payload2['max_ttl'] = max_ttl

        await self._post(['sys/auth', mount_path], payload=payload)
        await self._post(['auth', mount_path, 'config'], payload=payload2)

    async def map_team_policy(self, team_name: str, policies: List[str]):
        """
        Map a policy to a team

        :param team_name: Team name
        :param policies: Policies
        """
        team_name = team_name.lower().replace(' ', '-')

        payload = {'value': ','.join(policies)}

        await self._post([self.mount_path, 'map/teams', team_name], payload=payload)

    async def list_teams(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List Teams

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list([self.mount_path, 'map/teams'], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def get_team(self, team_name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Get team info

        :param team_name: Team name
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        team_name = team_name.lower().replace(' ', '-')

        response = await self._get([self.mount_path, 'map/teams', team_name], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def del_team(self, team_name: str):
        """
        Delete team

        :param team_name: Team name
        """
        team_name = team_name.lower().replace(' ', '-')

        await self._delete([self.mount_path, 'map/teams', team_name])

    async def map_user_policy(self, username: str, policies: List[str]):
        """
        Map policy to user

        :param username: Username
        :param policies: Policies
        """
        payload = {'value': ','.join(policies)}

        await self._post([self.mount_path, 'map/users', username], payload=payload)

    async def list_users(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List users

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list([self.mount_path, 'map/users'], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def get_user(self, user_name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Get user info

        :param user_name: Username
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        user_name = user_name.lower().replace(' ', '-')

        response = await self._get([self.mount_path, 'map/users', user_name], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def del_user(self, user_name: str):
        """
        Delete user

        :param user_name: Username
        """
        user_name = user_name.lower().replace(' ', '-')

        await self._delete([self.mount_path, 'map/users', user_name])

    async def login(self, token: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        GitHub token authentication

        :param token: Token
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._post([self.mount_path, 'login'], payload={'token': token}, wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)


class UserPassAuthBackend(HTTPBase):
    """
    Vault User/Password authentication backend
    """
    def __init__(self, *args, mount_path: str = 'userpass', **kwargs) -> None:
        super(UserPassAuthBackend, self).__init__(*args, **kwargs)

        self.mount_path = 'auth/' + mount_path

    async def mount(self, mount_path: str, description: str = ''):
        """
        Mount the user/password backend againt the given path

        :param mount_path: Mount path
        :param description: Description
        """
        payload = {
            'type': 'userpass',
            'description': description
        }
        await self._post(['sys/auth', mount_path], payload=payload)

    async def read(self, username: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Get user

        :param username: Username
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get([self.mount_path, 'users', username], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def create(self, username: str, password: str, policies: Optional[List[str]] = None, ttl: Optional[int] = None, max_ttl: Optional[int] = None):
        """
        Create user

        :param username: Username
        :param password: Password
        :param policies: Policies
        :param ttl: TTL
        :param max_ttl: Max TTL
        """
        payload = {
            'password': password,
        }
        if policies is not None:
            payload['policies'] = ','.join(policies)

        if ttl is not None:
            payload['ttl'] = ttl
        if max_ttl is not None:
            payload['max_ttl'] = max_ttl

        await self._post([self.mount_path, 'users', username], payload=payload)

    async def update(self, username: str, policies: Optional[List[str]] = None, ttl: Optional[int] = None, max_ttl: Optional[int] = None):
        """
        Update user

        :param username: Username
        :param policies: Policies
        :param ttl: TTL
        :param max_ttl: Max TTL
        """
        if policies is not None or ttl is not None or max_ttl is not None:
            payload = {}
            if policies is not None:
                payload['policies'] = ','.join(policies)
            if ttl is not None:
                payload['ttl'] = ttl
            if max_ttl is not None:
                payload['max_ttl'] = max_ttl

            await self._post([self.mount_path, 'users', username], payload=payload)

    async def delete(self, username: str):
        """
        Delete user

        :param username: Username
        """
        await self._delete([self.mount_path, 'users', username])

    async def update_password(self, username: str, password: str):
        """
        Update user password

        :param username: Username
        :param password: Password
        """
        await self._post([self.mount_path, 'users', username, 'password'], payload={'password': password})

    async def update_policies(self, username: str, policies: List[str]):
        """
        Update policies associated to a user

        :param username: Username
        :param policies: Policies
        """
        await self._post([self.mount_path, 'users', username, 'policies'], payload={'policies': ','.join(policies)})

    async def login(self, username: str, password: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Authenticate with username and password

        :param username: Username
        :param password: Password
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._post([self.mount_path, 'login', username], payload={'password': password}, wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def list(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List users

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list([self.mount_path, 'users'], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)


class RadiusAuthBackend(HTTPBase):
    """
    Vault RADIUS authentication backend
    """
    def __init__(self, *args, mount_path: str = 'radius', **kwargs) -> None:
        super(RadiusAuthBackend, self).__init__(*args, **kwargs)

        self.mount_path = 'auth/' + mount_path

    async def mount(self, mount_path: str, radius_host: str, secret: str, radius_port: int = 1812, unregistered_user_policies: Optional[List[str]] = None, dial_timeout: int = 10,
                    read_timeout: int = 10, nas_port: int = 10, description: str = ''):
        """
        Mount RADIUS authentication backend against the given path

        :param mount_path: Mount path
        :param radius_host: RADIUS host
        :param secret: RADIUS shared secret
        :param radius_port: RADIUS port
        :param unregistered_user_policies: Default policies for unregistered users
        :param dial_timeout: RADIUS dial timeout
        :param read_timeout: RADIUS read timeout
        :param nas_port: NAD port number
        :param description: Mount description
        """
        payload = {
            'type': 'radius',
            'description': description,
        }

        payload2 = {
            'host': radius_host,
            'port': radius_port,
            'secret': secret,
            'dial_timeout': dial_timeout,
            'read_timeout': read_timeout,
            'nas_port': nas_port

        }
        if unregistered_user_policies is not None:
            payload2['unregistered_user_policies'] = ','.join(unregistered_user_policies)

        await self._post(['sys/auth', mount_path], payload=payload)
        await self._post(['auth', mount_path, 'config'], payload=payload2)

    async def create(self, username: str, policies: Optional[List[str]] = None):
        """
        Create a user

        :param username: Username
        :param policies: Policies
        """
        payload = {}
        if policies is not None:
            payload['policies'] = ','.join(policies)

        await self._post([self.mount_path, 'users', username], payload=payload)

    async def update(self, username: str, policies: Optional[List[str]] = None):
        """
        Update policies associated to a user

        :param username: Username
        :param policies: Policies
        """
        await self.create(username, policies)

    async def read(self, username: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Get user

        :param username: Username
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get([self.mount_path, 'users', username], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def list(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List users

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list([self.mount_path, 'users'], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def delete(self, username: str):
        """
        Delete user

        :param username: Username
        """
        await self._delete([self.mount_path, 'users', username])

    async def login(self, username: str, password: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Authenticate with RADIUS using username and password

        :param username: Username
        :param password: Password
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        payload = {
            'username': username,
            'password': password
        }

        response = await self._post([self.mount_path, 'login'], payload=payload, wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)


class ApproleBackend(HTTPBase):
    """
    Vault AppRole authentication backend
    """
    def __init__(self, *args, mount_path: str = 'approle', **kwargs) -> None:
        super(ApproleBackend, self).__init__(*args, **kwargs)

        self.mount_path = 'auth/' + mount_path

    async def mount(self, mount_path: str, description: str = ''):
        """
        Mount AppRole backed against the given path

        :param mount_path: Mount path
        :param description: Mount description
        """
        payload = {
            'type': 'approle',
            'description': description,
        }

        await self._post(['sys/auth', mount_path], payload=payload)

    async def list(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List roles

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list([self.mount_path, 'role'], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def create(self, name: str, bind_secret_id: bool = True, bound_cidr_list: Optional[List[str]] = None, policies: Optional[List[str]] = None,
                     secret_id_num_uses: int = 0, secret_id_ttl: int = 0, token_num_uses: int = 0, token_ttl: int = 0, token_max_ttl: int = 0, period: int = 0):
        """
        Create AppRole

        :param name: Role Name
        :param bind_secret_id: Require secret_id to be presented when logging in using this AppRole
        :param bound_cidr_list: List of CIDR blocks
        :param policies: List of policies
        :param secret_id_num_uses: Number of times any particular SecretID can be used to fetch a token from this AppRole
        :param secret_id_ttl: Secret ID TTL
        :param token_num_uses: Number of times issued tokens can be used
        :param token_ttl: Token TTL
        :param token_max_ttl: Token Max TTL
        :param period: Periodic token TTL
        """
        payload = {
            'bind_secret_id': bind_secret_id,
            'secret_id_num_uses': secret_id_num_uses,
            'secret_id_ttl': secret_id_ttl,
            'token_num_uses': token_num_uses,
            'token_ttl': token_ttl,
            'token_max_ttl': token_max_ttl,
            'period': period
        }
        if bound_cidr_list is not None:
            payload['bound_cidr_list'] = ','.join(bound_cidr_list)
        if policies is not None:
            payload['policies'] = ','.join(policies)

        await self._post([self.mount_path, 'role', name], payload=payload)

    async def update(self, name: str, bind_secret_id: bool = True, bound_cidr_list: Optional[List[str]] = None, policies: Optional[List[str]] = None,
                     secret_id_num_uses: int = 0, secret_id_ttl: int = 0, token_num_uses: int = 0, token_ttl: int = 0, token_max_ttl: int = 0, period: int = 0):
        """
        Update AppRole

        :param name: Role Name
        :param bind_secret_id: Require secret_id to be presented when logging in using this AppRole
        :param bound_cidr_list: List of CIDR blocks
        :param policies: List of policies
        :param secret_id_num_uses: Number of times any particular SecretID can be used to fetch a token from this AppRole
        :param secret_id_ttl: Secret ID TTL
        :param token_num_uses: Number of times issued tokens can be used
        :param token_ttl: Token TTL
        :param token_max_ttl: Token Max TTL
        :param period: Periodic token TTL
        """
        await self.create(name, bind_secret_id, bound_cidr_list, policies, secret_id_num_uses, secret_id_ttl, token_num_uses, token_ttl, token_max_ttl, period)

    async def read(self, name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Get Role

        :param name: Role name
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get([self.mount_path, 'role', name], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def delete(self, name: str):
        """
        Delete role

        :param name: Role name
        """
        await self._delete([self.mount_path, 'role', name])

    async def read_roleid(self, name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Get role ID

        :param name: Role name
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get([self.mount_path, 'role', name, 'role-id'], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def set_roleid(self, name: str, role_id: str):
        """
        Set the role ID of a given role, overwriting what it was before

        :param name: Role name
        :param role_id: Role ID
        """
        await self._post([self.mount_path, 'role', name, 'role-id'], payload={'role_id': role_id})

    async def generate_secret_id(self, name: str, cidr_list: Optional[List[str]] = None, metadata: Optional[dict] = None, wrap_ttl: Optional[int] = None, custom_id: str = None) -> ResponseBase:
        """
        Generate random secret ID

        :param name: Role Name
        :param cidr_list: Optional list of CIDRs
        :param metadata: Secret ID metadata
        :param wrap_ttl: Wrap TTL
        :param custom_id: Custom secret ID instead of a randomly generated one
        :return: Response
        """
        payload = {

        }
        url_part = 'secret-id'

        if cidr_list is not None:
            payload['cidr_list'] = ','.join(cidr_list)
        if metadata is not None:
            payload['metadata'] = json.dumps(metadata)

        if custom_id is not None:
            url_part = 'custom-secret-id'
            payload['secret_id'] = custom_id

        response = await self._post([self.mount_path, 'role', name, url_part], payload=payload, wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def list_secret_ids(self, name: str, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List secret IDs for a given role

        :param name: Role name
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list([self.mount_path, 'role', name, 'secret-id'], wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def lookup_secret_id(self, name: str, secret_id: Optional[str] = None, secret_id_accessor: Optional[str] = None, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Lookup Secret ID

        :param name: Role name
        :param secret_id: Secret ID
        :param secret_id_accessor: Secret ID accessor
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        if secret_id is None and secret_id_accessor is None:
            raise ValueError('secret_id or secret_id_accessor must be provided')

        try:
            if secret_id is not None:
                response = await self._post([self.mount_path, 'role', name, 'secret-id/lookup'], payload={'secret_id': secret_id}, wrap_ttl=wrap_ttl)
            else:
                response = await self._post([self.mount_path, 'role', name, 'secret-id-accessor/lookup'], payload={'secret_id_accessor': secret_id_accessor}, wrap_ttl=wrap_ttl)
        except InternalServerError as err:  # Catch if accessor not found and convert into invalid path, theres probably a better way, its late, im tired.
            if 'failed to find accessor entry for secret_id' in str(err):
                raise InvalidPath("Secret does not exist")
            raise
        else:
            if response.status == 204:
                raise InvalidPath("Secret does not exist")
            else:
                json_data = await response.json()
                return ResponseBase(json_dict=json_data, request_func=self._request)

    async def destroy_secret_id(self, name: str, secret_id: Optional[str] = None, secret_id_accessor: Optional[str] = None):
        """
        Delete secret ID

        :param name: Role Name
        :param secret_id: Secret ID
        :param secret_id_accessor: Secret ID accessor
        :return:
        """
        if secret_id is None and secret_id_accessor is None:
            raise ValueError('secret_id or secret_id_accessor must be provided')

        if secret_id is not None:
            await self._post([self.mount_path, 'role', name, 'secret-id/destroy'], payload={'secret_id': secret_id})
        else:
            await self._post([self.mount_path, 'role', name, 'secret-id-accessor/destroy'], payload={'secret_id_accessor': secret_id_accessor})

    async def login(self, role_id: str, secret_id: Optional[str] = None, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Authenticate with the AppRole backend


        :param role_id: Role ID
        :param secret_id: Secret ID (if cidr isnt used)
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        payload = {
            'role_id': role_id
        }
        if secret_id is not None:
            payload['secret_id'] = secret_id

        response = await self._post([self.mount_path, 'login'], payload=payload, wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)


class TokenAuthBackend(HTTPBase):
    """
    Vault Token authentication backend
    """
    async def list_accessors(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List token accessors

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list(['auth/token/accessors'], wrap_ttl=wrap_ttl)
        json_data = await response.json()

        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def create(self, name: Optional[str] = None, policies: Optional[List[str]] = None, role: Optional[str] = None,
                     no_parent: bool = False, display_name: Optional[str] = None, meta: Optional[Dict[str, str]] = None,
                     num_uses: int = 0, no_default_policy: bool = False, ttl: Optional[str] = None,
                     orphan: bool = False, wrap_ttl: Optional[int] = None, renewable: Optional[bool] = None,
                     explicit_max_ttl: Optional[int] = None, period: Optional[str] = None) -> ResponseBase:
        """
        Create token

        :param name: Optional token ID
        :param policies: Token policies
        :param role: Role
        :param no_parent: Creates an orphan token
        :param display_name: Token display name
        :param meta: Additional data
        :param num_uses: Number of uses
        :param no_default_policy: If no default policy is to be added
        :param ttl: TTL
        :param orphan: Orphan token
        :param wrap_ttl: Wrap TTL
        :param renewable: Is renewable
        :param explicit_max_ttl: Max TTL
        :param period: TTL period
        :return: Response
        """

        payload = {
            'id': name,
            'policies': policies,
            'meta': meta,
            'no_parent': no_parent,
            'display_name': display_name,
            'num_uses': num_uses,
            'no_default_policy': no_default_policy,
            'renewable': renewable
        }
        if ttl is not None:
            payload['ttl'] = ttl
        elif period is not None:
            payload['perios'] = period
        if explicit_max_ttl is not None:
            payload['explicit_max_ttl'] = explicit_max_ttl

        if orphan:
            response = await self._post('auth/token/create-orphan', payload=payload, wrap_ttl=wrap_ttl)
        elif role is not None:
            response = await self._post(['auth/token/create', role], payload=payload, wrap_ttl=wrap_ttl)
        else:
            response = await self._post('auth/token/create', payload=payload, wrap_ttl=wrap_ttl)

        # TODO possibly set ResponseBase.__getitem__ to use .auth instead of .data for token create responses
        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def lookup(self, token: Optional[str] = None, accessor: Optional[str] = None, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Lookup token

        :param token: Token ID
        :param accessor: Token accessor
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        if token is None and accessor is None:
            raise ValueError("Token and Accessor cannot both be none")

        if token is not None:
            # Token Lookup
            response = await self._post('auth/token/lookup', payload={'token': token}, wrap_ttl=wrap_ttl)

            json_data = await response.json()
            return ResponseBase(json_dict=json_data, request_func=self._request)

        # Accessor lookup
        response = await self._post('auth/token/lookup-accessor', payload={'accessor': accessor}, wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def lookup_self(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Lookup active token info

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get('auth/token/lookup', wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def renew(self, token: str, increment: Optional[int] = None, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Renew token

        :param token: Token
        :param increment: Increment to lease
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        payload = {
            'token': token,
        }
        if increment is not None:
            payload['increment'] = increment

        response = await self._post('auth/token/renew', payload=payload, wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def renew_self(self, increment: Optional[int] = None, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        Renew currently active token

        :param increment: Increment to lease
        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        if increment is not None:
            response = await self._post('auth/token/renew-self', payload={'increment': increment}, wrap_ttl=wrap_ttl)
        else:
            response = await self._post('auth/token/renew-self', payload={}, wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def revoke(self, token: Optional[str] = None, accessor: Optional[str] = None, orphan: bool = False):
        """
        Revoke token

        :param token: Token
        :param accessor: Token accessor
        :param orphan: Orphan token
        """
        if token is None and accessor is None:
            raise ValueError("Token and Accessor cannot both be none")

        if token is not None:
            if orphan:
                await self._post('auth/token/revoke-orphan', payload={'token': token})
            else:
                await self._post('auth/token/revoke', payload={'token': token})
        else:
            await self._post('auth/token/revoke-accessor', payload={'accessor': accessor})

    async def revoke_self(self):
        """
        Revoke currently active token
        """
        await self._post('auth/token/revoke-self', payload=None)

    async def list_roles(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List token roles

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._list('auth/token/roles', wrap_ttl=wrap_ttl)

        json_data = await response.json()
        return ResponseBase(json_dict=json_data, request_func=self._request)

    async def create_role(self, name: str, allowed_policies: Optional[List[str]] = None, disallowed_policies: Optional[List[str]] = None,
                          orphan: bool = False, period: Optional[str] = None, renewable: bool = False, path_suffix: Optional[str] = None,
                          explicit_max_ttl: Optional[str] = None):
        """
        Create token role

        :param name: Role name
        :param allowed_policies: Allowed policies
        :param disallowed_policies: Disallowed policies, allows you to do "you can have these policies if you dont have these"
        :param orphan: Tokens created with this will be orphans
        :param period: Period TTL
        :param renewable: Is renewable
        :param path_suffix: Role name will have this suffix
        :param explicit_max_ttl: Max TTL
        :return: Response
        """
        payload = {
            'allowed_policies': allowed_policies,
            'disallowed_policies': disallowed_policies,
            'orphan': orphan,
            'period': period,
            'renewable': renewable,
            'path_suffix': path_suffix,
            'explicit_max_ttl': explicit_max_ttl
        }
        await self._post(['auth/token/roles', name], payload=payload)

    async def delete_role(self, name: str):
        """
        Delete token role

        :param name: Role name
        """
        await self._delete(['auth/token/roles', name])

    async def tidy(self):
        """
        Run tidy operation
        """
        await self._post('auth/token/tidy')


class BaseAuth(HTTPBase):
    """
    Base authentication class, basically contains references to the other authentication backends as well as the capability to list the authentication backends.
    """
    def __init__(self, *args, **kwargs) -> None:
        super(BaseAuth, self).__init__(*args, **kwargs)
        self._args = args
        self._kwargs = kwargs

        self._token = None
        self._userpass = None
        self._github = None
        self._approle = None
        self._radius = None
        self._ldap = None

    @property
    def token(self) -> TokenAuthBackend:
        """
        Get Token backend

        :return: Token backend
        """
        if self._token is None:
            self._token = TokenAuthBackend(*self._args, **self._kwargs)

        return self._token

    @property
    def userpass(self) -> UserPassAuthBackend:
        """
        Get UserPass backend

        :return: UserPass backend
        """
        if self._userpass is None:
            self._userpass = UserPassAuthBackend(*self._args, **self._kwargs)

        return self._userpass

    @property
    def github(self) -> GitHubAuthBackend:
        """
        Get GitHub backend

        :return: GitHub backend
        """
        if self._github is None:
            self._github = GitHubAuthBackend(*self._args, **self._kwargs)

        return self._github

    @property
    def approle(self) -> ApproleBackend:
        """
        Get AppRole backend

        :return: AppRole backend
        """
        if self._approle is None:
            self._approle = ApproleBackend(*self._args, **self._kwargs)

        return self._approle

    @property
    def radius(self) -> RadiusAuthBackend:
        """
        Get RADIUS backend

        :return: RADIUS backend
        """
        if self._radius is None:
            self._radius = RadiusAuthBackend(*self._args, **self._kwargs)

        return self._radius

    @property
    def ldap(self) -> LDAPAuthBackend:
        """
        Get LDAP backend

        :return: LDAP backend
        """
        if self._ldap is None:
            self._ldap = LDAPAuthBackend(*self._args, **self._kwargs)

        return self._ldap

    async def list_backends(self, wrap_ttl: Optional[int] = None) -> ResponseBase:
        """
        List auth backends

        :param wrap_ttl: Wrap TTL
        :return: Response
        """
        response = await self._get('sys/auth', wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    def get_userpass_backend(self, mount_path) -> UserPassAuthBackend:
        """
        Get UserPass backend

        :param mount_path: Mount path
        :return: UserPass backend
        """
        return UserPassAuthBackend(*self._args, mount_path=mount_path, **self._kwargs)

    def get_github_backend(self, mount_path) -> GitHubAuthBackend:
        """
        Get GitHub backend

        :param mount_path: Mount path
        :return: GitHub backend
        """
        return GitHubAuthBackend(*self._args, mount_path=mount_path, **self._kwargs)

    def get_approle_backend(self, mount_path) -> ApproleBackend:
        """
        Get AppRole backend

        :param mount_path: Mount path
        :return: AppRole backend
        """
        return ApproleBackend(*self._args, mount_path=mount_path, **self._kwargs)

    def get_radius_backend(self, mount_path) -> RadiusAuthBackend:
        """
        Get RADIUS backend

        :param mount_path: Mount path
        :return: RADIUS backend
        """
        return RadiusAuthBackend(*self._args, mount_path=mount_path, **self._kwargs)

    def get_ldap_backend(self, mount_path) -> LDAPAuthBackend:
        """
        Get LDAP backend

        :param mount_path: Mount path
        :return: LDAP backend
        """
        return LDAPAuthBackend(*self._args, mount_path=mount_path, **self._kwargs)
