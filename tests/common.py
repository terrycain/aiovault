from tests import run_vault


class BaseTestCase(object):
    proc = None
    config = None

    @classmethod
    def setup_class(cls):
        cls.proc = run_vault.VaultProc(config=cls.config)
        cls.proc.run()

        return cls()

    @classmethod
    def teardown_class(cls):
        cls.proc.stop()


class NoTLSTestCase(BaseTestCase):
    config = 'vault_no_tls.hcl'
