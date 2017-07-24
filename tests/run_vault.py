#!/usr/bin/env python3
import os
import subprocess
import shutil
import sys
import time
import zipfile

import requests

VAULT_CONF_FOLDER = os.path.join(os.path.dirname(__file__), 'config')
VAULT_VERSION = "0.7.3"
CONSUL_VERSION = "0.9.0"


class VaultProc:
    VAULT_ZIP = "vault_{0}_linux_amd64.zip".format(VAULT_VERSION)
    VAULT_DOWNLOAD_URL = "https://releases.hashicorp.com/vault/{0}/{1}".format(VAULT_VERSION, VAULT_ZIP)
    CONSUL_ZIP = "consul_{0}_linux_amd64.zip".format(CONSUL_VERSION)
    CONSUL_DOWNLOAD_URL = "https://releases.hashicorp.com/consul/{0}/{1}".format(CONSUL_VERSION, CONSUL_ZIP)

    def __init__(self, config=None, consul_config=None):
        self._get_vault()

        if config is None:
            self.config = None
        else:
            self.config = os.path.join(VAULT_CONF_FOLDER, config)

        if consul_config is None:
            self.consul_config = None
        else:
            self.consul_config = os.path.join(VAULT_CONF_FOLDER, consul_config)
            self._get_consul()

        self.unseal_keys = None
        self.root_token = None
        self.vault_proc = None
        self.consul_proc = None
        self.consul_master_acl_token = 'master_token'

    def _get_vault(self):
        if not os.path.exists('./vault'):
            response = requests.get(self.VAULT_DOWNLOAD_URL, stream=True)
            if response.status_code != 200:
                print("Failed to download vault")
                sys.exit(1)

            with open('vault.zip', 'wb') as vault_zip:
                response.raw.decode_content = True
                shutil.copyfileobj(response.raw, vault_zip)

            zip_obj = zipfile.ZipFile('vault.zip')
            zip_obj.extract('vault')

            os.remove('vault.zip')
            os.chmod('./vault', 0o0755)

    def _get_consul(self):
        if not os.path.exists('./consul'):
            response = requests.get(self.CONSUL_DOWNLOAD_URL, stream=True)
            if response.status_code != 200:
                print("Failed to download consul")
                sys.exit(1)

            with open('consul.zip', 'wb') as consul_zip:
                response.raw.decode_content = True
                shutil.copyfileobj(response.raw, consul_zip)

            zip_obj = zipfile.ZipFile('consul.zip')
            zip_obj.extract('consul')

            os.remove('consul.zip')
            os.chmod('./consul', 0o0755)

    def run(self, quiet=True):
        if self.config is not None:
            self._run_prod(quiet)
        else:
            self._run_dev(quiet)

    def _run_prod(self, quiet=True):
        if self.consul_config is not None:
            self.consul_proc = subprocess.Popen(['./consul', 'agent', '-dev', '-config-file={0}'.format(self.consul_config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.vault_proc = subprocess.Popen(['./vault', 'server', '-config={0}'.format(self.config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if not quiet:
            print("Vault started")
            print("No keys as not initialised")

    def _run_dev(self, quiet=True):
        if self.consul_config is not None:
            self.consul_proc = subprocess.Popen(['./consul', 'agent', '-dev', '-config-file={0}'.format(self.consul_config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.vault_proc = subprocess.Popen(['./vault', 'server', '-dev'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        while True:
            line = self.vault_proc.stdout.readline().decode()
            if line.startswith('Unseal Key'):
                self.unseal_key = line.strip().split(': ')[1]
                continue

            if line.startswith('Root Token'):
                self.root_token = line.strip().split(': ')[1]
                break

        if not quiet:
            print("Vault started")
            print("Unseal key: {0}\nRoot token: {1}".format(self.unseal_key, self.root_token))

    def run_interactive(self):
        self.run(quiet=False)
        print("Waiting for Ctrl+C")

        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            pass

        self.stop()

    def stop(self):
        if self.vault_proc is not None and self.vault_proc.poll() is None:
            self.vault_proc.kill()

        if self.consul_proc is not None and self.consul_proc.poll() is None:
            self.consul_proc.kill()

    def __del__(self):
        self.stop()


if __name__ == '__main__':
    vault_proc = VaultProc()
    vault_proc.run_interactive()
