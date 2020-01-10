"""Sans-I/O implementation of SOCKS4, SOCKS4A, and SOCKS5."""

from .exceptions import ProtocolError, SOCKSError
from .socks4 import (
    SOCKS4Command,
    SOCKS4Connection,
    SOCKS4Reply,
    SOCKS4ReplyCode,
    SOCKS4Request,
)
from .socks5 import (
    SOCKS5AType,
    SOCKS5AuthMethod,
    SOCKS5AuthReply,
    SOCKS5AuthRequest,
    SOCKS5Command,
    SOCKS5Connection,
    SOCKS5Reply,
    SOCKS5ReplyCode,
    SOCKS5Request,
)

__version__ = "0.1.1"

__all__ = [
    "SOCKS5Request",
    "SOCKS5ReplyCode",
    "SOCKS5Connection",
    "SOCKS5Command",
    "SOCKS5AuthRequest",
    "SOCKS5AuthReply",
    "SOCKS5AuthMethod",
    "SOCKS5AType",
    "SOCKS5Reply",
    "SOCKS4Request",
    "SOCKS4Reply",
    "SOCKS4Connection",
    "SOCKS4Command",
    "SOCKS4ReplyCode",
    "SOCKSError",
    "ProtocolError",
]
