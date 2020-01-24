import pytest

from socksio.socks5 import SOCKS5AType
from socksio.utils import AddressType, split_address_port_from_string


@pytest.mark.parametrize(
    "socks5_atype,expected",
    [
        (SOCKS5AType.IPV4_ADDRESS, AddressType.IPV4),
        (SOCKS5AType.IPV6_ADDRESS, AddressType.IPV6),
        (SOCKS5AType.DOMAIN_NAME, AddressType.DN),
    ],
)
def test_address_type_from_socks5atype(
    socks5_atype: SOCKS5AType, expected: AddressType
) -> None:
    assert AddressType.from_socks5_atype(socks5_atype) == expected


def test_socks5atype_unknown_address_type_raises() -> None:
    with pytest.raises(ValueError):
        AddressType.from_socks5_atype("FOOBAR")


@pytest.mark.parametrize(
    "address_str,expected_address,expected_port",
    [
        ("127.0.0.1:8080", "127.0.0.1", 8080),
        ("[0:0:0:0:0:0:0:1]:3080", "0:0:0:0:0:0:0:1", 3080),
    ],
)
def test_split_address_port_from_string(
    address_str, expected_address, expected_port
) -> None:
    assert split_address_port_from_string(address_str) == (
        expected_address,
        expected_port,
    )


@pytest.mark.parametrize(
    "address_str", ["127.0.0.1", "::1", "127.0.0.1:", "[::1]:foobar"]
)
def test_split_address_port_from_string_errors(address_str) -> None:
    with pytest.raises(ValueError):
        split_address_port_from_string(address_str)
