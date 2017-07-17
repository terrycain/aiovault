#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `aiovault` package."""
import os
import pytest
import aiovault
import aiovault.base

from .common import BaseTestCase


class TestBaseAuth(BaseTestCase):
    async def test_list_auth_backends(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.auth.list_backends()
        assert 'token/' in result


class TestGitHubAuth(BaseTestCase):
    @pytest.mark.run(order=1)
    async def test_mount_userpass(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.github.mount('github', organization='openrazer', description='test_mount')
        result = await client.auth.list_backends()
        assert 'github/' in result
        assert result['github/']['description'] == 'test_mount'

    async def test_map_team_policy(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.github.map_team_policy('test_map', ['default'])
        result = await client.auth.github.list_teams()
        assert 'keys' in result
        assert 'test_map' in result['keys']

    async def test_get_team(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.github.map_team_policy('test_read', ['default'])
        result = await client.auth.github.get_team('test_read')
        assert 'value' in result
        assert result['value'] == 'default'

    async def test_del_team(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.github.map_team_policy('test_del', ['default'])
        result = await client.auth.github.get_team('test_del')
        assert 'value' in result

        await client.auth.github.del_team('test_del')

        result = await client.auth.github.get_team('test_del')
        assert 'value' not in result

    async def test_map_user_policy(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.github.map_user_policy('test_map_user', ['default'])
        result = await client.auth.github.list_teams()
        assert 'keys' in result
        assert 'test_map' in result['keys']

    async def test_get_user(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.github.map_user_policy('test_read_user', ['default'])
        result = await client.auth.github.get_user('test_read_user')
        assert 'value' in result
        assert result['value'] == 'default'

    async def test_del_user(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.github.map_user_policy('test_del_user', ['default'])
        result = await client.auth.github.get_user('test_del_user')
        assert 'value' in result

        await client.auth.github.del_user('test_del_user')

        result = await client.auth.github.get_user('test_del_user')
        assert 'value' not in result

    @pytest.mark.skipif('GITHUB_OAUTH_KEY' not in os.environ, reason="Skipping as no GitHub key")
    async def test_login(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.github.map_user_policy('terrycain', ['default'])
        token_obj = await client.auth.github.login(os.environ['GITHUB_OAUTH_KEY'])
        assert 'client_token' in token_obj.auth
        assert 'metadata' in token_obj.auth
        assert token_obj.auth['metadata']['username'] == 'terrycain'


class TestUserPassAuth(BaseTestCase):
    @pytest.mark.run(order=1)
    async def test_mount_userpass(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.userpass.mount('userpass')
        result = await client.auth.list_backends()
        assert 'userpass/' in result

    async def test_create_user(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.userpass.create('test_create', 'test1234')
        result = await client.auth.userpass.list()
        assert 'keys' in result
        assert 'test_create' in result['keys']

    async def test_read_user(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.userpass.create('test_read', 'test1234')
        result = await client.auth.userpass.read('test_read')
        assert 'policies' in result
        assert result['policies'] == ''

    async def test_update_user(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.userpass.create('test_update', 'test1234')
        await client.auth.userpass.update('test_update', policies=['default'])
        result = await client.auth.userpass.read('test_update')
        assert 'policies' in result
        assert result['policies'] == 'default'

    async def test_update_policies(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.userpass.create('test_update_pol', 'test1234')
        await client.auth.userpass.update_policies('test_update_pol', policies=['default'])
        result = await client.auth.userpass.read('test_update_pol')
        assert 'policies' in result
        assert result['policies'] == 'default'

    async def test_delete_user(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.userpass.create('test_delete', 'test1234')
        await client.auth.userpass.delete('test_delete')
        with pytest.raises(aiovault.exceptions.InvalidPath):
            await client.auth.userpass.read('test_delete')

    async def test_login(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.userpass.create('test_login', 'test1234')
        token_obj = await client.auth.userpass.login('test_login', 'test1234')

        # TODO perhaps point __getitem__ to auth
        assert 'client_token' in token_obj.auth
        assert 'metadata' in token_obj.auth
        assert token_obj.auth['metadata']['username'] == 'test_login'

    async def test_update_password(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.userpass.create('test_updatepw', 'test1234')
        await client.auth.userpass.update_password('test_updatepw', 'password')

        # TODO perhaps point __getitem__ to auth
        token_obj = await client.auth.userpass.login('test_updatepw', 'password')
        assert 'client_token' in token_obj.auth


class TestTokenAuth(BaseTestCase):
    async def test_list_accessor(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.auth.token.list_accessors()
        assert 'keys' in result
        assert isinstance(result['keys'], list)

    async def test_create_token(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.auth.token.create(display_name='test_create')
        assert result.auth is not None
        assert 'client_token' in result.auth
        assert 'accessor' in result.auth

    async def test_create_orphan_token(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.auth.token.create(orphan=True, display_name='test_orphan')
        assert result.auth is not None
        assert 'client_token' in result.auth
        assert 'accessor' in result.auth

    async def test_token_lookup(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        token = await client.auth.token.create(display_name='test-lookup')
        token_id = token.auth['client_token']

        lookup_result = await client.auth.token.lookup(token=token_id)
        assert token_id == lookup_result['id']
        assert lookup_result['display_name'] == 'token-' + 'test-lookup'

    async def test_token_lookup_accessor(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        token = await client.auth.token.create(display_name='test-lookup-accessor')
        accessor_id = token.auth['accessor']

        lookup_result = await client.auth.token.lookup(accessor=accessor_id)
        assert accessor_id == lookup_result['accessor']
        assert lookup_result['display_name'] == 'token-' + 'test-lookup-accessor'

    async def test_lookup_self(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        lookup_result = await client.auth.token.lookup_self()
        assert lookup_result['display_name'] == 'root'
        assert lookup_result['id'] == self.proc.root_token

    async def test_renew(self, loop):
        root_client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        token = await root_client.auth.token.create(ttl=60, renewable=True)
        lookup_result = await root_client.auth.token.lookup(token=token.auth['client_token'])
        await root_client.auth.token.renew(token.auth['client_token'], increment='120s')
        lookup_result2 = await root_client.auth.token.lookup(token=token.auth['client_token'])

        assert lookup_result['expire_time'] != lookup_result2['expire_time']

    async def test_renew_self(self, loop):
        with aiovault.VaultClient(token=self.proc.root_token, loop=loop) as root_client:
            token = await root_client.auth.token.create(ttl=60, renewable=True)

        new_client = aiovault.VaultClient(token=token.auth['client_token'], loop=loop)

        lookup_result = await new_client.auth.token.lookup_self()
        await new_client.auth.token.renew_self()
        lookup_result2 = await new_client.auth.token.lookup_self()

        assert lookup_result['expire_time'] != lookup_result2['expire_time']

    async def test_revoke(self, loop):
        root_client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        token = await root_client.auth.token.create(ttl=60, renewable=True)
        await root_client.auth.token.revoke(token=token.auth['client_token'])

        with pytest.raises(aiovault.exceptions.Forbidden):
            await root_client.auth.token.lookup(token=token.auth['client_token'])

    async def test_revoke_accessor(self, loop):
        root_client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        token = await root_client.auth.token.create(ttl=60, renewable=True)
        await root_client.auth.token.revoke(accessor=token.auth['accessor'])

        with pytest.raises(aiovault.exceptions.Forbidden):
            await root_client.auth.token.lookup(token=token.auth['client_token'])

    async def test_revoke_self(self, loop):
        root_client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        token = await root_client.auth.token.create(ttl=60, renewable=True)
        client = aiovault.VaultClient(token=token.auth['client_token'], loop=loop)
        await client.auth.token.revoke_self()

        with pytest.raises(aiovault.exceptions.Forbidden):
            await root_client.auth.token.lookup(token=token.auth['client_token'])

    async def test_revoke_and_orphan(self, loop):
        root_client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        token = await root_client.auth.token.create(ttl=120, renewable=True)
        client = aiovault.VaultClient(token=token.auth['client_token'], loop=loop)
        sub_token = await client.auth.token.create(ttl=120, renewable=True)

        await root_client.auth.token.revoke(token=token.auth['client_token'], orphan=True)

        await root_client.auth.token.lookup(token=sub_token.auth['client_token'])

        with pytest.raises(aiovault.exceptions.Forbidden):
            await root_client.auth.token.lookup(token=token.auth['client_token'])

    async def test_create_role(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.token.create_role('test_create_role')

        # list_roles raises 404 if no roles
        result = await client.auth.token.list_roles()
        assert 'keys' in result
        assert 'test_create_role' in result['keys']

    async def test_delete_role(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.token.create_role('test_create_role')
        await client.auth.token.list_roles()
        await client.auth.token.delete_role('test_create_role')
        with pytest.raises(aiovault.exceptions.InvalidPath):
            await client.auth.token.list_roles()

    async def test_tidy(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.token.tidy()
