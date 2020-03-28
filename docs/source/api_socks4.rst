.. _SOCKS4-API-documentation:

.. currentmodule:: socksio.socks4

SOCKS4 and SOCKS4A API documentation
====================================

SOCKS4 and SOCKS4A are almost identical protocols, as such the API is implemented
in a single module and most components are shared.

The only practical difference is the usage of a :class:`SOCKS4Request` versus
:class:`SOCKS4Request`.

Remember SOCKS4 allows only for IPv4 addresses and SOCKS4A supports domain names.
Neither support IPv6.

.. automodule:: socksio.socks4
   :members:
