from tests import run_vault


class BaseTestCase(object):
    proc = None

    @classmethod
    def setup_class(cls):
        cls.proc = run_vault.VaultProc()
        cls.proc.run()

        return cls()

    @classmethod
    def teardown_class(cls):
        cls.proc.stop()
