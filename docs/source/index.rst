socksio: Client-side sans-I/O SOCKS proxy implementation
========================================================

``socksio`` is a sans-I/O library similar to
`h11`_ or `h2`_, this means the
library itself does not handle the actual sending of the bytes through
the network, it only deals with the implementation details of the SOCKS
protocols so you can use it in any I/O library you want.

Current status: alpha
---------------------

The API is not final and may be subject to change.

Features not yet implemented:

-  SOCKS5 GSS-API authentication.
-  SOCKS5 UDP associate requests.

Contents
--------

.. toctree::
   :maxdepth: 2

   usage.rst

.. _h11: https://github.com/python-hyper/h11
.. _h2: https://github.com/python-hyper/hyper-h2/