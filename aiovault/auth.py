from typing import Optional, List, Dict

from .base import HTTPBase, ResponseBase


class GitHubAuthBackend(HTTPBase):
    def __init__(self, *args, mount_path: str='github', **kwargs) -> None:
        super(GitHubAuthBackend, self).__init__(*args, **kwargs)

        self.mount_path = 'auth/' + mount_path

    async def mount(self, mount_path: str, organization: str, description: str='', base_url: Optional[str]=None, ttl: Optional[str]=None, max_ttl: Optional[str]=None):
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
        team_name = team_name.lower().replace(' ', '-')

        payload = {'value': ','.join(policies)}

        await self._post([self.mount_path, 'map/teams', team_name], payload=payload)

    async def list_teams(self, wrap_ttl: Optional[int]=None) -> ResponseBase:
        response = await self._list([self.mount_path, 'map/teams'], wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def get_team(self, team_name: str, wrap_ttl: Optional[int]=None) -> ResponseBase:
        team_name = team_name.lower().replace(' ', '-')

        response = await self._get([self.mount_path, 'map/teams', team_name], wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def del_team(self, team_name: str):
        team_name = team_name.lower().replace(' ', '-')

        await self._delete([self.mount_path, 'map/teams', team_name])

    async def map_user_policy(self, username: str, policies: List[str]):
        payload = {'value': ','.join(policies)}

        await self._post([self.mount_path, 'map/users', username], payload=payload)

    async def list_users(self, wrap_ttl: Optional[int]=None) -> ResponseBase:
        response = await self._list([self.mount_path, 'map/users'], wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def get_user(self, team_name: str, wrap_ttl: Optional[int]=None) -> ResponseBase:
        team_name = team_name.lower().replace(' ', '-')

        response = await self._get([self.mount_path, 'map/users', team_name], wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def del_user(self, team_name: str):
        team_name = team_name.lower().replace(' ', '-')

        await self._delete([self.mount_path, 'map/users', team_name])

    async def login(self, token: str, wrap_ttl: Optional[int]=None) -> ResponseBase:
        response = await self._post([self.mount_path, 'login'], payload={'token': token}, wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)


class UserPassAuthBackend(HTTPBase):
    def __init__(self, *args, mount_path: str='userpass', **kwargs) -> None:
        super(UserPassAuthBackend, self).__init__(*args, **kwargs)

        self.mount_path = 'auth/' + mount_path

    async def mount(self, mount_path: str, description: str=''):
        payload = {
            'type': 'userpass',
            'description': description
        }
        await self._post(['sys/auth', mount_path], payload=payload)

    async def read(self, username: str, wrap_ttl: Optional[int]=None) -> ResponseBase:
        response = await self._get([self.mount_path, 'users', username], wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def create(self, username: str, password: str, policies: Optional[List[str]]=None, ttl: Optional[int]=None, max_ttl: Optional[int]=None):
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

    async def update(self, username: str, policies: Optional[List[str]]=None, ttl: Optional[int]=None, max_ttl: Optional[int]=None):
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
        await self._delete([self.mount_path, 'users', username])

    async def update_password(self, username: str, password: str):
        await self._post([self.mount_path, 'users', username, 'password'], payload={'password': password})

    async def update_policies(self, username: str, policies: List[str]):
        await self._post([self.mount_path, 'users', username, 'policies'], payload={'policies': ','.join(policies)})

    async def login(self, username: str, password: str, wrap_ttl: Optional[int]=None) -> ResponseBase:
        response = await self._post([self.mount_path, 'login', username], payload={'password': password}, wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def list(self, wrap_ttl: Optional[int]=None) -> ResponseBase:
        response = await self._list([self.mount_path, 'users'], wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)


class TokenAuthBackend(HTTPBase):
    async def list_accessors(self, wrap_ttl: Optional[int]=None) -> ResponseBase:
        response = await self._list(['auth/token/accessors'], wrap_ttl=wrap_ttl)
        json = await response.json()

        return ResponseBase(json_dict=json, request_func=self._request)

    async def create(self, name: Optional[str]=None, policies: Optional[List[str]]=None, role: Optional[str]=None,
                     no_parent: bool=False, display_name: Optional[str]=None, meta: Optional[Dict[str, str]]=None,
                     num_uses: int=0, no_default_policy: bool=False, ttl: Optional[str]=None,
                     orphan: bool=False, wrap_ttl: Optional[int]=None, renewable: Optional[bool]=None,
                     explicit_max_ttl: Optional[int]=None, period: Optional[str]=None) -> ResponseBase:

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
        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def lookup(self, token: Optional[str]=None, accessor: Optional[str]=None, wrap_ttl: Optional[int]=None) -> ResponseBase:
        if token is None and accessor is None:
            raise ValueError("Token and Accessor cannot both be none")

        if token is not None:
            response = await self._post('auth/token/lookup', payload={'token': token}, wrap_ttl=wrap_ttl)

            json = await response.json()
            return ResponseBase(json_dict=json, request_func=self._request)
        else:
            response = await self._post('auth/token/lookup-accessor', payload={'accessor': accessor}, wrap_ttl=wrap_ttl)

            json = await response.json()
            return ResponseBase(json_dict=json, request_func=self._request)

    async def lookup_self(self, wrap_ttl: Optional[int]=None) -> ResponseBase:
        response = await self._get('auth/token/lookup', wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def renew(self, token: str, increment: Optional[int]=None, wrap_ttl: Optional[int]=None) -> ResponseBase:
        payload = {
            'token': token,
        }
        if increment is not None:
            payload['increment'] = increment

        response = await self._post('auth/token/renew', payload=payload, wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def renew_self(self, increment: Optional[int]=None, wrap_ttl: Optional[int]=None) -> ResponseBase:
        if increment is not None:
            response = await self._post('auth/token/renew-self', payload={'increment': increment}, wrap_ttl=wrap_ttl)
        else:
            response = await self._post('auth/token/renew-self', payload={}, wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def revoke(self, token: Optional[str]=None, accessor: Optional[str]=None, orphan: bool=False):
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
        await self._post('auth/token/revoke-self', payload=None)

    async def list_roles(self, wrap_ttl: Optional[int]=None) -> ResponseBase:
        response = await self._list('auth/token/roles', wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    async def create_role(self, name: str, allowed_policies: Optional[List[str]]=None, disallowed_policies: Optional[List[str]]=None,
                          orphan: bool=False, period: Optional[str]=None, renewable: bool=False, path_suffix: Optional[str]=None,
                          explicit_max_ttl: Optional[str]=None):
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
        await self._delete(['auth/token/roles', name])

    async def tidy(self):
        await self._post('auth/token/tidy')


class BaseAuth(HTTPBase):
    def __init__(self, *args, **kwargs) -> None:
        super(BaseAuth, self).__init__(*args, **kwargs)
        self._args = args
        self._kwargs = kwargs

        self._token = None
        self._userpass = None
        self._github = None

    @property
    def token(self) -> TokenAuthBackend:
        if self._token is None:
            self._token = TokenAuthBackend(*self._args, **self._kwargs)

        return self._token

    @property
    def userpass(self) -> UserPassAuthBackend:
        if self._userpass is None:
            self._userpass = UserPassAuthBackend(*self._args, **self._kwargs)

        return self._userpass

    @property
    def github(self) -> GitHubAuthBackend:
        if self._github is None:
            self._github = GitHubAuthBackend(*self._args, **self._kwargs)

        return self._github

    async def list_backends(self, wrap_ttl: Optional[int]=None) -> ResponseBase:
        response = await self._get('sys/auth', wrap_ttl=wrap_ttl)

        json = await response.json()
        return ResponseBase(json_dict=json, request_func=self._request)

    def get_userpass_backend(self, mount_path) -> UserPassAuthBackend:
        return UserPassAuthBackend(*self._args, mount_path=mount_path, **self._kwargs)

    def get_github_backend(self, mount_path) -> GitHubAuthBackend:
        return GitHubAuthBackend(*self._args, mount_path=mount_path, **self._kwargs)
