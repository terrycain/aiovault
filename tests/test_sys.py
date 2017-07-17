#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `aiovault` package."""
import aiovault
import aiovault.base

from .common import BaseTestCase


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

    # Needs special Vault
    # async def test_seal_status(self, loop):
    #     client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)
    #
    #     result = await client.sys.seal_status()
    #
    #     assert isinstance(audit_collection, aiovault.base.ResponseBase)
    #     assert name + '/' in audit_collection
    #
    #     file_mount = audit_collection[name + '/']
    #     assert file_mount['description'] == desc
    #     assert file_mount['options']['path'] == path

    # Needs special Vault
    # async def test_init(self, loop):
    #     client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)
    #
    #     result = await client.sys.initialize(secret_shares=7, secret_threshold=2)
    #
    #     print()
