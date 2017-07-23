#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `aiovault` package."""
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
