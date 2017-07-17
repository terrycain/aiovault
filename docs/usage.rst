===========
Basic Usage
===========

To get started with using vault you first need to import AIOVault and initialise a client. The client object can also be used as a context manager so it all can be used with the `with` statement.

.. code-block:: python

    import aiovault

    with aiovault.VaultClient(token='6c84fb90-12c4-11e1-840d-7b25c5ee775a') as client:
        is_authed = await client..is_authenticated()
        print(is_authed)  # True

        await client.secrets.generic.create('some_secret', key1='value1', key2='value2')
        secret = await client.secrets.generic.read('some_secret')

        print(secret['key1'])  # value1
        print(secret['key2'])  # value2



