#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `aiovault` package."""
import os
import asyncio
import pytest
import aiovault
import aiovault.base

from .common import BaseTestCase


class TestBasic(BaseTestCase):
    async def test_token_auth_success(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.is_authenticated()

        assert result

    async def test_token_auth_failure(self, loop):
        client = aiovault.VaultClient(token=None, loop=loop)

        result = await client.is_authenticated()

        assert not result

    async def test_logout(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.is_authenticated()
        assert result

        client.logout()
        assert client._auth_token is None

        result = await client.is_authenticated()
        assert not result


class TestBaseSecretBackend(BaseTestCase):
    async def test_list_secret_backends(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.secrets.list()

        assert 'secret/' in result
        assert 'cubbyhole/' in result
        assert 'sys/' in result

    async def test_mount_generic_backend(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.mount(
            path='test_generic',
            description='test_mount'
        )

        result = await client.secrets.list()

        assert 'test_generic/' in result
        assert 'test_mount' in result['test_generic/']['description']

    async def test_get_mounted_generic_backend(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.mount(path='test_generic2')

        new_mount = client.secrets.get_generic_secret_backend('test_generic2')

        await new_mount.create('test_mount', key1='value1')
        secret = await new_mount.read('test_mount')

        assert isinstance(secret, aiovault.base.ResponseBase)
        assert 'key1' in secret

        # Check its not in the generic /secret backend
        with pytest.raises(aiovault.exceptions.InvalidPath):
            await client.secrets.generic.read('test_mount')


class TestGenericSecretBackend(BaseTestCase):
    async def test_create_secret(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.create('test/create/test1', value='test')
        await client.secrets.generic.create('test/create/test2', value='test')

    async def test_read_secret(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.create('test/read/test1', key1='value1', key2='value2')

        secret = await client.secrets.generic.read('test/read/test1')

        assert isinstance(secret, aiovault.base.ResponseBase)
        assert 'key1' in secret
        assert 'key2' in secret
        assert secret['key1'] == 'value1'
        assert secret['key2'] == 'value2'

    async def test_list_secret(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.create('test/list/test1', key1='value1')
        await client.secrets.generic.create('test/list/test2', key2='value2')
        await client.secrets.generic.create('test/list/test3/test4', key2='value2')

        secret = await client.secrets.generic.list('test/list')

        # Should show us keys test1, test2 and directory test3/
        assert isinstance(secret, aiovault.base.ResponseBase)
        assert 'keys' in secret
        for key_name in ('test1', 'test2', 'test3/'):
            assert key_name in secret['keys']

    async def test_secret_ttl(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)
        # Generic secret backend will not automatically remove values

        await client.secrets.generic.create('test/ttl/test1', key1='value1', ttl=3)

        secret = await client.secrets.generic.read('test/ttl/test1')

        assert 'ttl' in secret
        assert secret['ttl'] == 3
        assert secret.lease_duration == 3

    async def test_update_secret(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.create('test/update/test1', key1='value1')
        # Normal vault will do an overwrite on update with generic secret backend
        await client.secrets.generic.update('test/update/test1', key2='value2')

        secret = await client.secrets.generic.read('test/update/test1')

        assert 'key1' in secret
        assert 'key2' in secret
        assert secret['key1'] == 'value1'
        assert secret['key2'] == 'value2'

    async def test_delete_secret(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.create('test/read/test1', key1='value1')

        secret = await client.secrets.generic.read('test/read/test1')

        assert 'key1' in secret

        await client.secrets.generic.delete('test/read/test1')

        with pytest.raises(aiovault.exceptions.InvalidPath):
            await client.secrets.generic.read('test/read/test1')

    async def test_list_wrapped_secret(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.create('test/list/test1', key1='value1')
        await client.secrets.generic.create('test/list/test2', key2='value2')
        await client.secrets.generic.create('test/list/test3/test4', key2='value2')

        secret = await client.secrets.generic.list('test/list', wrap_ttl=60)

        assert secret.is_wrapped

        await secret.unwrap()

        assert not secret.is_wrapped
        assert 'keys' in secret
        for key_name in ('test1', 'test2', 'test3/'):
            assert key_name in secret['keys']

    async def test_read_wrapped_secret(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.create('test/read/test1', key1='value1', key2='value2')

        secret = await client.secrets.generic.read('test/read/test1', wrap_ttl=60)

        assert secret.is_wrapped

        await secret.unwrap()

        assert not secret.is_wrapped
        assert 'key1' in secret
        assert 'key2' in secret
        assert secret['key1'] == 'value1'
        assert secret['key2'] == 'value2'

    @pytest.mark.skipif('SLOW_TESTS' not in os.environ, reason="Skipping slow tests by default")
    async def test_wrapped_secret_expire(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.create('test/read/test1', key1='value1', key2='value2')

        secret = await client.secrets.generic.read('test/read/test1', wrap_ttl=1)

        assert secret.is_wrapped

        await asyncio.sleep(2, loop=loop)

        with pytest.raises(aiovault.exceptions.VaultWrapExpired):
            await secret.unwrap()

    async def test_read_rewrapped_secret(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.create('test/read_wrapped/test1', key1='value1')

        secret = await client.secrets.generic.read('test/read_wrapped/test1', wrap_ttl=60)

        assert secret.is_wrapped
        initial_token = secret.wrap_info['token']

        await secret.rewrap()
        assert initial_token != secret.wrap_info['token']

        await secret.unwrap()

        assert not secret.is_wrapped
        assert 'key1' in secret
        assert secret['key1'] == 'value1'
