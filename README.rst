================================
Async library for Hasicorp Vault
================================


.. image:: https://img.shields.io/pypi/v/aiovault.svg
  :target: https://pypi.python.org/pypi/aiovault

.. image:: https://img.shields.io/travis/terrycain/aiovault.svg
  :target: https://travis-ci.org/terrycain/aiovault

.. image:: https://codecov.io/gh/terrycain/aiovault/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/terrycain/aiovault

.. image:: https://readthedocs.org/projects/pyaiovault/badge/?version=latest
  :target: https://pyaiovault.readthedocs.io
  :alt: Documentation Status

.. image:: https://pyup.io/repos/github/terrycain/aiovault/shield.svg
  :target: https://pyup.io/repos/github/terrycain/aiovault/
  :alt: Updates

.. image:: https://pyup.io/repos/github/terrycain/aiovault/python-3-shield.svg
  :target: https://pyup.io/repos/github/terrycain/aiovault/
  :alt: Python 3

aiovault 0.1.X release
======================

This is the inital release, aimed to get started with PyPI.

There is some basic support of Vault features. The interface is sorta stable, I kinda like where its going. Most if not all methods use the Python3's typing module to add type hinting.


Example
=======

Simple example of authenticating with vault and then writing then reading a secret

.. code-block:: python

    import aiovault

    with aiovault.VaultClient(token='6c84fb90-12c4-11e1-840d-7b25c5ee775a') as client:
        is_authed = await client.is_authenticated()
        print(is_authed)  # True

        await client.secrets.generic.create('some_secret', key1='value1', key2='value2')

        secret = await client.secrets.generic.read('some_secret')

        print(secret['key1'])  # value1
        print(secret['key2'])  # value2


Documentation
=============

https://pyaiovault.readthedocs.io/en/latest/

Features
--------

- Token, GitHub and User/Password Authentication backends
- Generic Secret backend
- File and Syslog Audit backends
- Policy management
- Backend renaming


TODO (Near future)
------------------

- Secret backends: Transit, TOTP, Consul
- Auth backends: AppRole, LDAP, Radius, MFA
- Tests for vault initialisation, sealing and rekeying

TODO (Long term)
----------------

- More docs, more examples
- Possibly utility functions like a coroutine to keep renewing a token/secret
- Policy validation with hcl library?
- Socket audit backend
- Okta, TLS and AWS auth support
- Database, PKI, RabbitMQ, SSH secret support


Credits
-------

I used the cookiecutter package to setup the initial project. Was pretty good.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage


License
=======

* Free software: GNU General Public License v3
* Documentation: https://aiovault.readthedocs.io.
