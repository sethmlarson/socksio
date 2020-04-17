socksio: Client-side sans-I/O SOCKS proxy implementation
========================================================

``socksio`` is a sans-I/O library similar to
`h11 <https://github.com/python-hyper/h11>`_ or
`h2 <https://github.com/python-hyper/hyper-h2/>`_, this means the
library itself does not handle the actual sending of the bytes through
the network, it only deals with the implementation details of the SOCKS
protocols so you can use it in any I/O library you want.

Current status: stable
----------------------

Features not yet implemented:

-  SOCKS5 GSS-API authentication.
-  SOCKS5 UDP associate requests.

Contents
--------

.. toctree::
   :maxdepth: 2

   usage.rst
   development.rst
   api_socks4.rst
   api_socks5.rst

Reference documents
-------------------

Each implementation follows the documents as listed below:

-  SOCKS4: https://www.openssh.com/txt/socks4.protocol
-  SOCKS4A: https://www.openssh.com/txt/socks4a.protocol
-  SOCKS5: https://www.ietf.org/rfc/rfc1928.txt
-  SOCKS5 username/password authentication:
   https://www.ietf.org/rfc/rfc1929.txt
-  SOCKS5 GSS-API authentication: https://www.ietf.org/rfc/rfc1961.txt

License
-------

MIT
