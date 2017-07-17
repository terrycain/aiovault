"""
Collection of exceptions to split out some of the errors Vault could throw
"""


class VaultError(Exception):
    """
    Generic catch-all Vault exception
    """
    def __init__(self, message=None, errors=None):
        if errors:
            message = ', '.join(errors)

        self.errors = errors

        super(VaultError, self).__init__(message)


class InvalidRequest(VaultError):
    """
    Invalid Request Exception
    """


class Unauthorized(VaultError):
    """
    Unauthorized Exception
    """


class Forbidden(VaultError):
    """
    Forbidden Exception
    """


class InvalidPath(VaultError):
    """
    Invalid Path Exception
    """


class RateLimitExceeded(VaultError):
    """
    Rate Limit Exceeded Exception
    """


class InternalServerError(VaultError):
    """
    Internal Server Exception
    """


class VaultNotInitialized(VaultError):
    """
    Vault not initialized exception
    """


class VaultDown(VaultError):
    """
    Vault down exception
    """


class UnexpectedError(VaultError):
    """
    Any other error
    """


class VaultWrapExpired(VaultError):
    """
    Error if trying to unwrap an exception after expiry
    """
