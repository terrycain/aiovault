#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `aiovault` package."""
import pytest
import asyncio
import aiovault
import aiovault.base

from .common import BaseTestCase, NoTLSTestCase


class TestBaseSys(BaseTestCase):
    async def test_remount(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.generic.mount(path='test_generic_rename')
        result = await client.secrets.list()
        assert 'test_generic_rename/' in result

        await client.sys.remount('test_generic_rename', 'test_generic_rename2')
        result = await client.secrets.list()
        assert 'test_generic_rename/' not in result
        assert 'test_generic_rename2/' in result


# Running these tests in order purely as it simplifies things
class TestSysInit(NoTLSTestCase):
    @pytest.mark.run(order=1)
    async def test_init(self, loop):
        await asyncio.sleep(2, loop=loop)

        client = aiovault.VaultClient(token=None, loop=loop)

        init_result = await client.sys.initialize(secret_shares=7, secret_threshold=4)

        assert 'root_token' in init_result
        assert 'keys' in init_result

        self.proc.root_token = init_result['root_token']
        self.proc.unseal_keys = init_result['keys']

    @pytest.mark.run(order=2)
    async def test_seal_status(self, loop):
        client = aiovault.VaultClient(token=None, loop=loop)

        result = await client.sys.seal_status()

        assert 'sealed' in result
        assert result['sealed']
        assert 'progress' in result
        assert 't' in result
        assert 'n' in result

    @pytest.mark.run(order=3)
    async def test_unseal(self, loop):
        client = aiovault.VaultClient(token=None, loop=loop)

        result = await client.sys.unseal(self.proc.unseal_keys[0])
        assert result['progress'] == 1
        result = await client.sys.unseal(self.proc.unseal_keys[1])
        assert result['progress'] == 2
        result = await client.sys.unseal(None)
        assert result['progress'] == 0

        await client.sys.unseal(self.proc.unseal_keys[0])  # 1
        await client.sys.unseal(self.proc.unseal_keys[1])  # 2
        await client.sys.unseal(self.proc.unseal_keys[2])  # 3
        result = await client.sys.unseal(self.proc.unseal_keys[3])  # 3

        assert not result['sealed']

    @pytest.mark.run(order=4)
    async def test_seal(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.sys.seal_status()
        assert not result['sealed']

        await client.sys.seal()

        result = await client.sys.seal_status()
        assert result['sealed']

        await client.sys.unseal(self.proc.unseal_keys[0])  # 1
        await client.sys.unseal(self.proc.unseal_keys[1])  # 2
        await client.sys.unseal(self.proc.unseal_keys[2])  # 3
        result = await client.sys.unseal(self.proc.unseal_keys[3])  # 3

        assert not result['sealed']

    @pytest.mark.run(order=5)
    async def test_rotate(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.sys.rotate()

    @pytest.mark.run(order=6)
    async def test_health(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.sys.health()

        assert 'cluster_id' in result
        assert 'cluster_name' in result
        assert 'initialized' in result
        assert 'sealed' in result
        assert 'standby' in result
        assert 'version' in result

        assert not result['sealed']
