import pytest

from socksio.socks5 import SOCKS5AType
from socksio.utils import AddressType


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
