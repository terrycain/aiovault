#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `aiovault` package."""
import os
import pytest
import aiovault
import aiovault.base

from .common import BaseTestCase


class TestBaseAudit(BaseTestCase):
    async def test_backend_file_add(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        name = 'fileaudit'
        desc = 'Unittest Add'
        path = '/tmp/vaultaudit_unittest.log'

        await client.audit.file.mount(
            mount_path=name,
            filepath=path,
            description=desc,
        )

        audit_collection = await client.audit.list()

        assert isinstance(audit_collection, aiovault.base.ResponseBase)
        assert name + '/' in audit_collection

        file_mount = audit_collection[name + '/']
        assert file_mount['description'] == desc
        assert file_mount['options']['path'] == path

    @pytest.mark.skipif("TRAVIS" in os.environ, reason="Skipping this test on Travis CI.")
    async def test_backend_syslog_add(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        name = 'syslogaudit'
        desc = 'Unittest Add'
        tag = 'vaultsyslog'

        await client.audit.syslog.mount(mount_path=name, description=desc, tag=tag)

        audit_collection = await client.audit.list()

        assert isinstance(audit_collection, aiovault.base.ResponseBase)
        assert name + '/' in audit_collection

        file_mount = audit_collection[name + '/']
        assert file_mount['description'] == desc
        assert file_mount['options']['tag'] == tag

    async def test_backend_del(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        name = 'fileaudit_del'
        await client.audit.file.mount(mount_path=name, filepath='/tmp/vaultaudit_unittest_del.log', description='Unittest Del')

        audit_collection = await client.audit.list()
        assert name + '/' in audit_collection

        await client.audit.delete(name + '/')

        audit_collection = await client.audit.list()
        assert name + '/' not in audit_collection

    async def test_backend_hash(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        name = 'fileaudit_hash'
        await client.audit.file.mount(mount_path=name, filepath='/tmp/vaultaudit_unittest_hash.log', description='Unittest Hash')

        audit_collection = await client.audit.list()
        assert name + '/' in audit_collection

        result = await client.audit.hash(name, 'test1')

        assert 'hash' in result
        assert result['hash'].startswith('hmac-sha256')
