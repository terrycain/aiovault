================================
Async library for Hasicorp Vault
================================


.. image:: https://img.shields.io/pypi/v/aiovault.svg
  :target: https://pypi.python.org/pypi/aiovault

.. image:: https://img.shields.io/pypi/dm/aiovault.svg
  :target: https://pypi.python.org/pypi/aiovault

.. image:: https://img.shields.io/travis/terrycain/aiovault/master.svg?label=master%20build
  :target: https://travis-ci.org/terrycain/aiovault

.. image:: https://img.shields.io/travis/terrycain/aiovault/stable.svg?label=stable%20build
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

aiovault 1.0.0 release
======================

First major release. Should be pretty stable... all the tests pass so cant be too bad.

This library is mainly just a glorified wrapper around aiohttp calling the many Vault URLs. Eventually I want to add some helper methods to make using vault with microservices easier, like
having a coroutine which will just sit there renewing tokens/secrets etc...

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

- Token, GitHub, AppRole, LDAP, RADIUS and User/Password Authentication backends
- Generic Secret, Consul, TOTP and Transit backends
- File and Syslog Audit backends
- Policy management
- Backend renaming
- Initialization, seal and health management


TODO (Near future)
------------------

- Improve code coverage
- Secret backends: Databases, RabbitMQ, Cubbyhole
- Auth backends: Okta, AWS (hopefully)

TODO (Long term)
----------------

- More docs, more examples
- Possibly utility functions like a coroutine to keep renewing a token/secret
- Policy validation with hcl library?
- Socket audit backend
- TLS auth support
- PKI, SSH secret support

Testing
-------

As many of the unit tests that can, interact directly with Vault/Consul/LDAP/RADIUS without mocking. Currently my reasoning is that this way, if we change the variable that
determins the vault version and incompatabilites in the REST interface were introduced they would appear immediatly in the masses of failing unit tests.

Credits
-------

I used the _Cookiecutter package to setup the initial project. Was pretty good.

And most of the credit goes to the wonderful _aiohttp library which this library is pretty much a wrapper around.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _aiohttp: https://github.com/aio-libs/aiohttp


License
=======

* Free software: GNU General Public License v3
* Documentation: https://aiovault.readthedocs.io.
