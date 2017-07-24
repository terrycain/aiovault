from tests import run_vault


class BaseTestCase(object):
    proc = None
    config = None
    consul_config = None

    @classmethod
    def setup_class(cls):
        cls.proc = run_vault.VaultProc(config=cls.config, consul_config=cls.consul_config)
        cls.proc.run()

        return cls()

    @classmethod
    def teardown_class(cls):
        cls.proc.stop()


class NoTLSTestCase(BaseTestCase):
    config = 'vault_no_tls.hcl'


class ConsulTestCase(BaseTestCase):
    consul_config = 'consul_server.json'
