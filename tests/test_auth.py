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


class TestAppRoleAuth(BaseTestCase):
    @pytest.mark.run(order=1)
    async def test_mount_approle(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.mount('approle', description='test_mount')
        result = await client.auth.list_backends()
        assert 'approle/' in result
        assert result['approle/']['description'] == 'test_mount'

    async def test_approle_list(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_create')

        result = await client.auth.approle.list()
        assert 'keys' in result
        assert 'test_create' in result['keys']

    async def test_approle_read(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_read')

        result = await client.auth.approle.read('test_read')
        assert 'bind_secret_id' in result
        assert 'policies' in result
        assert 'default' in result['policies']

    async def test_approle_update(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_update')
        await client.auth.approle.update('test_update', bind_secret_id=False, bound_cidr_list=['172.16.30.0/24', '172.16.31.0/24'])
        result = await client.auth.approle.read('test_update')
        assert not result['bind_secret_id']
        assert result['bound_cidr_list'] == '172.16.30.0/24,172.16.31.0/24'

    async def test_approle_delete(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_delete')
        await client.auth.approle.read('test_delete')
        await client.auth.approle.delete('test_delete')

        with pytest.raises(aiovault.exceptions.InvalidPath):
            await client.auth.approle.read('test_delete')

    async def test_approle_read_role_id(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_read_role_id')
        result = await client.auth.approle.read_roleid('test_read_role_id')
        assert 'role_id' in result

    async def test_approle_set_role_id(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_set_role_id')
        await client.auth.approle.set_roleid('test_set_role_id', 'new_role_id')
        result = await client.auth.approle.read_roleid('test_set_role_id')
        assert 'role_id' in result
        assert result['role_id'] == 'new_role_id'

    async def test_approle_generate_secret_id(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_gen_secret_id')
        result = await client.auth.approle.generate_secret_id('test_gen_secret_id')
        assert 'secret_id_accessor' in result
        assert 'secret_id' in result

    async def test_approle_generate_custom_secret_id(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_custom_secret_id')
        result = await client.auth.approle.generate_secret_id('test_custom_secret_id', custom_id='test1234')
        assert 'secret_id_accessor' in result
        assert 'secret_id' in result
        assert result['secret_id'] == 'test1234'

    async def test_approle_list_secret_id(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_list_secret_id')
        sec_id_result = await client.auth.approle.generate_secret_id('test_list_secret_id')

        result = await client.auth.approle.list_secret_ids('test_list_secret_id')
        assert 'keys' in result
        assert sec_id_result['secret_id_accessor'] in result['keys']

    async def test_approle_lookup_secret_id(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_lookup_secret_id')
        sec_id_result = await client.auth.approle.generate_secret_id('test_lookup_secret_id', metadata={'test1': 'value1'})

        result = await client.auth.approle.lookup_secret_id('test_lookup_secret_id', secret_id=sec_id_result['secret_id'])
        assert 'creation_time' in result
        assert 'metadata' in result
        assert result['metadata']['test1'] == 'value1'

    async def test_approle_lookup_secret_id_accessor(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_lookup_secret_id_accessor')
        sec_id_result = await client.auth.approle.generate_secret_id('test_lookup_secret_id_accessor', metadata={'test2': 'value2'})

        result = await client.auth.approle.lookup_secret_id('test_lookup_secret_id_accessor', secret_id_accessor=sec_id_result['secret_id_accessor'])
        assert 'creation_time' in result
        assert 'metadata' in result
        assert result['metadata']['test2'] == 'value2'

    async def test_approle_destroy_secret_id(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_destroy_secret_id')
        sec_id_result = await client.auth.approle.generate_secret_id('test_destroy_secret_id', metadata={'test3': 'value3'})

        await client.auth.approle.destroy_secret_id('test_destroy_secret_id', secret_id=sec_id_result['secret_id'])

        with pytest.raises(aiovault.exceptions.InvalidPath):
            await client.auth.approle.lookup_secret_id('test_destroy_secret_id', secret_id=sec_id_result['secret_id'])

    async def test_approle_destroy_secret_id_accessor(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_destroy_secret_id_accessor')
        sec_id_result = await client.auth.approle.generate_secret_id('test_destroy_secret_id_accessor', metadata={'test4': 'value4'})

        await client.auth.approle.destroy_secret_id('test_destroy_secret_id_accessor', secret_id_accessor=sec_id_result['secret_id_accessor'])

        with pytest.raises(aiovault.exceptions.InvalidPath):
            await client.auth.approle.lookup_secret_id('test_destroy_secret_id_accessor', secret_id_accessor=sec_id_result['secret_id_accessor'])

    async def test_login(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.auth.approle.create('test_login')
        role_result = await client.auth.approle.read_roleid('test_login')
        assert 'role_id' in role_result

        secret_result = await client.auth.approle.generate_secret_id('test_login')
        assert 'secret_id' in secret_result

        login_result = await client.auth.approle.login(role_id=role_result['role_id'], secret_id=secret_result['secret_id'])
        assert 'client_token' in login_result.auth
        assert 'accessor' in login_result.auth
