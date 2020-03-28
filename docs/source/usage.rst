Usage
-----

.. currentmodule:: socksio

TL;DR check the `examples directory
<https://github.com/sethmlarson/socksio/tree/master/examples/>`_.

Being sans-I/O means that in order to test ``socksio`` you need an I/O
library. And the most basic I/O is, of course, the standard library’s
``socket`` module.

You’ll need to know ahead of time the type of SOCKS proxy you want to
connect to. Assuming we have a SOCKS4 proxy running in our machine on
port 8080, we will first create a connection to it:

.. code:: python

    import socket

    sock = socket.create_connection(("localhost", 8080))

``socksio`` exposes modules for SOCKS4, SOCKS4A and SOCKS5, each of them
includes a ``Connection`` class:

.. code:: python

    from socksio import socks4

    # The SOCKS4 protocol requires a `user_id` to be supplied.
    conn = socks4.SOCKS4Connection(user_id=b"socksio")

Since ``socksio`` is a sans-I/O library, we will use the socket to send
and receive data to our SOCKS4 proxy. The raw data, however, will be
created and parsed by our :class:`SOCKS4Connection <socks4.SOCKS4Connection>`.

We need to tell our connection we want to make a request to the proxy.
We do that by first creating a request object.

In SOCKS4 we only need to send a command along with an IP address and
port. ``socksio`` exposes the different types of commands as enumerables
and a convenience :meth:`~socks4.SOCKS4Request.from_address`
class method in the request classes to create a valid request object:

.. code:: python

    # SOCKS4 does not allow domain names, below is an IP for google.com
    request = socks4.SOCKS4Request.from_address(
        socks4.SOCKS4Command.CONNECT, ("216.58.204.78", 80))

``from_address`` methods are available on all request classes in
``socksio``, they accept addresses as tuples of ``(address, port)`` as
well as string ``address:port``.

Now we ask the connection to send our request:

.. code:: python

    conn.send(request)

The :class:`SOCKS4Connection <socks4.SOCKS4Connection>` will then compose the
necessary ``bytes`` in the proper format for us to send to our proxy:

.. code:: python

    data = conn.data_to_send()
    sock.sendall(data)

If all goes well the proxy will have sent reply, we just need to read
from the socket and pass the data to the
:class:`SOCKS4Connection <socks4.SOCKS4Connection>`:

.. code:: python

    data = sock.recv(1024)
    event = conn.receive_data(data)

The connection will parse the data and return an event from it, in this
case, a :class:`SOCKS4Reply <socks4.SOCKS4Reply>` that includes attributes for
the fields in the SOCKS reply:

.. code:: python

    if event.reply_code != socks4.SOCKS4ReplyCode.REQUEST_GRANTED:
        raise Exception(
            "Server could not connect to remote host: {}".format(event.reply_code)
        )

If all went well the connection has been established correctly and we
can start sending our request directly to the proxy:

.. code:: python

    sock.sendall(b"GET / HTTP/1.1\r\nhost: google.com\r\n\r\n")
    data = receive_data(sock)
    print(data)
    # b'HTTP/1.1 301 Moved Permanently\r\nLocation: http://www.google.com/...`

The same methodology is used for all protocols, check out the
`examples directory <https://github.com/sethmlarson/socksio/tree/master/examples/>`_
for more information.
