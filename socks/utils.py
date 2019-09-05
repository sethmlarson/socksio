import enum
import functools
import socket
import typing


class SOCKSError(Exception):
    """Generic exception for when something goes wrong"""


class AddressType(enum.Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DN = "DN"


@functools.lru_cache(maxsize=64)
def encode_address(addr: str) -> typing.Tuple[AddressType, bytes]:
    """Determines the type of address and encodes it into the format SOCKS expects"""
    try:
        return AddressType.IPV6, socket.inet_pton(socket.AF_INET6, addr)
    except OSError:
        try:
            return AddressType.IPV4, socket.inet_pton(socket.AF_INET, addr)
        except OSError:
            return AddressType.DN, addr.encode()


@functools.lru_cache(maxsize=64)
def decode_address(address_type: AddressType, encoded_addr: bytes) -> str:
    """Decodes the address from a SOCKS reply"""
    if address_type == AddressType.IPV6:
        return socket.inet_ntop(socket.AF_INET6, encoded_addr)
    elif address_type == AddressType.IPV4:
        return socket.inet_ntop(socket.AF_INET, encoded_addr)
    else:
        assert address_type == AddressType.DN
        return encoded_addr.decode()
