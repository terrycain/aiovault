#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `aiovault` package."""
import aiovault
import aiovault.base

from .common import BaseTestCase


class TestBasePolicy(BaseTestCase):
    async def test_list(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.policies.list()
        assert 'policies' in result
        assert 'root' in result['policies']

    async def test_read(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        result = await client.policies.read('root')
        assert result['name'] == 'root'
        assert result['rules'] == ''

    async def test_create(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        policy = 'path "secret/*" { capabilities = ["read"] }'
        await client.policies.create('test_create', rules=policy)

        result = await client.policies.read('test_create')
        assert result['name'] == 'test_create'
        assert result['rules'] == policy

    async def test_update(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        policy1 = 'path "secret/*" { capabilities = ["read"] }'
        policy2 = 'path "secret/*" { capabilities = ["read", "list"] }'
        await client.policies.create('test_update', rules=policy1)
        await client.policies.update('test_update', rules=policy2)

        result = await client.policies.read('test_update')
        assert result['name'] == 'test_update'
        assert result['rules'] == policy2

    async def test_delete(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        policy = 'path "secret/*" { capabilities = ["read"] }'
        await client.policies.create('test_delete', rules=policy)
        await client.policies.delete('test_delete')
