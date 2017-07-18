#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `aiovault` package."""
import os
import asyncio
import pytest
import aiovault
import aiovault.base
import binascii
import base64

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


class TestTransitSecretBackend(BaseTestCase):
    @pytest.mark.run(order=1)
    async def test_mount_transit(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.mount('transit', description='test_mount_transit')
        result = await client.secrets.list()
        assert 'transit/' in result

    async def test_create_key(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_create_key', key_type='ecdsa-p256')

        result = await client.secrets.transit.read('test_create_key')

        assert 'name' in result
        assert result['name'] == 'test_create_key'
        assert 'type' in result
        assert result['type'] == 'ecdsa-p256'

    async def test_list_key(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_list_key')

        result = await client.secrets.transit.list()

        assert 'keys' in result
        assert 'test_list_key' in result['keys']

    async def test_update_key(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_update_key', key_type='ecdsa-p256')
        await client.secrets.transit.update('test_update_key', deletion_allowed=True)

        result = await client.secrets.transit.read('test_update_key')

        assert result['name'] == 'test_update_key'
        assert result['deletion_allowed']

    async def test_delete_key(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_delete_key')

        result = await client.secrets.transit.list()
        assert 'test_delete_key' in result['keys']

        with pytest.raises(aiovault.exceptions.InvalidRequest):
            await client.secrets.transit.delete('test_delete_key')

        await client.secrets.transit.update('test_delete_key', deletion_allowed=True)
        await client.secrets.transit.delete('test_delete_key')

        result = await client.secrets.transit.list()
        assert 'test_delete_key' not in result['keys']

    async def test_rotate_key(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_rotate_key')

        before_rotate = await client.secrets.transit.read('test_rotate_key')
        await client.secrets.transit.rotate('test_rotate_key')
        after_rotate = await client.secrets.transit.read('test_rotate_key')

        assert '1' in before_rotate['keys']
        assert '2' not in before_rotate['keys']
        assert '1' in after_rotate['keys']
        assert '2' in after_rotate['keys']

    async def test_export_key(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_export_key', exportable=True)

        result = await client.secrets.transit.export('test_export_key', 'encryption-key')

        assert 'name' in result
        assert 'keys' in result
        assert 'type' in result

    async def test_encryption(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_enc_key', exportable=True)

        result = await client.secrets.transit.encrypt('test_enc_key', 'test1234')

        assert 'ciphertext' in result

    async def test_batch_encryption(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_batch_enc_key', exportable=True)

        encode = [{'plaintext': 'test1234'}, {'plaintext': '4321dcba'}]
        result = await client.secrets.transit.encrypt('test_batch_enc_key', '', batch_input=encode)

        assert 'batch_results' in result

    async def test_decryption(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_dec_key', exportable=True)

        enc_result = await client.secrets.transit.encrypt('test_dec_key', 'test1234')

        dec_result = await client.secrets.transit.decrypt('test_dec_key', enc_result['ciphertext'])

        assert 'plaintext' in dec_result
        assert dec_result['plaintext'] == 'test1234'

    async def test_batch_decryption(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_batch_dec_key', exportable=True)

        encode = [{'plaintext': 'test1234'}, {'plaintext': '4321dcba'}]
        enc_result = await client.secrets.transit.encrypt('test_batch_dec_key', '', batch_input=encode)

        dec_result = await client.secrets.transit.decrypt('test_batch_dec_key', '', batch_input=enc_result['batch_results'])

        for pre_enc, post_dec in zip(encode, dec_result['batch_results']):
            assert pre_enc['plaintext'] == post_dec['plaintext']

    async def test_rewrap(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_rewrap_key', exportable=True)

        enc_result = await client.secrets.transit.encrypt('test_rewrap_key', 'test1234')
        assert enc_result['ciphertext'].startswith('vault:v1')

        await client.secrets.transit.rotate('test_rewrap_key')
        wrapped_result = await client.secrets.transit.rewrap('test_rewrap_key', enc_result['ciphertext'])
        assert wrapped_result['ciphertext'].startswith('vault:v2')

        dec_result = await client.secrets.transit.decrypt('test_rewrap_key', wrapped_result['ciphertext'])
        assert dec_result['plaintext'] == 'test1234'

    async def test_rewrap_batch(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_batch_rewrap_key', exportable=True)

        encode = [{'plaintext': 'test1234'}, {'plaintext': '4321dcba'}]
        enc_result = await client.secrets.transit.encrypt('test_batch_rewrap_key', '', batch_input=encode)
        await client.secrets.transit.rotate('test_batch_rewrap_key')
        wrapped_result = await client.secrets.transit.rewrap('test_batch_rewrap_key', '', batch_input=enc_result['batch_results'])

        dec_result = await client.secrets.transit.decrypt('test_batch_rewrap_key', '', batch_input=wrapped_result['batch_results'])
        for pre_enc, post_dec in zip(encode, dec_result['batch_results']):
            assert pre_enc['plaintext'] == post_dec['plaintext']

    async def test_generate_key_data(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_get_data_key')

        wrapped_data = await client.secrets.transit.generate_key_data('test_get_data_key')
        assert 'ciphertext' in wrapped_data

        plaintext_data = await client.secrets.transit.generate_key_data('test_get_data_key', result_type='plaintext')
        assert 'ciphertext' in plaintext_data
        assert 'plaintext' in plaintext_data

    async def test_generate_random_data(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        bytes_result = await client.secrets.transit.generate_random_bytes(length=32, result_format='bytes')
        hex_result = await client.secrets.transit.generate_random_bytes(length=8, result_format='hex')
        base64_result = await client.secrets.transit.generate_random_bytes(length=16, result_format='base64')

        assert isinstance(bytes_result['random_bytes'], bytes)
        hex_data = binascii.unhexlify(hex_result['random_bytes'])
        assert len(hex_data) == 8
        base64_data = base64.b64decode(base64_result['random_bytes'].encode())
        assert len(base64_data) == 16

    async def test_generate_hmac(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_hmac_key')

        result = await client.secrets.transit.generate_hmac('test_hmac_key', 'test1234', result_format='base64')
        assert 'hmac' in result

    async def test_sign_data(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_sign_key', key_type='ecdsa-p256')

        result = await client.secrets.transit.sign('test_sign_key', 'test1234')
        assert 'signature' in result

    async def test_verify_signature(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_verify_sig_key', key_type='ecdsa-p256')

        sig_result = await client.secrets.transit.sign('test_verify_sig_key', 'test1234', algorithm='sha2-256')
        sig_verify_result = await client.secrets.transit.verify('test_verify_sig_key', 'test1234', signature=sig_result['signature'], algorithm='sha2-256')

        assert sig_verify_result['valid']

    async def test_verify_hmac(self, loop):
        client = aiovault.VaultClient(token=self.proc.root_token, loop=loop)

        await client.secrets.transit.create('test_verify_hmac_key', key_type='ecdsa-p256')

        hmac_result = await client.secrets.transit.generate_hmac('test_verify_hmac_key', 'test1234', algorithm='sha2-256')
        hmac_verify_result = await client.secrets.transit.verify('test_verify_hmac_key', 'test1234', hmac=hmac_result['hmac'], algorithm='sha2-256')

        assert hmac_verify_result['valid']
