import pytest

from socks import (
    ProtocolError,
    SOCKS5AuthMethod,
    SOCKS5AuthRequest,
    SOCKS5Connection,
    SOCKS5AuthReply,
)


def test_socks5_auth_request() -> None:
    conn = SOCKS5Connection()
    auth_methods = [SOCKS5AuthMethod.GSSAPI, SOCKS5AuthMethod.USERNAME_PASSWORD]

    conn.authenticate(auth_methods)

    data = conn.data_to_send()
    assert len(data) == 4
    assert data[0:1] == b"\x05"
    assert data[1:2] == len(auth_methods).to_bytes(1, byteorder="big")
    assert data[2:3] == SOCKS5AuthMethod.GSSAPI
    assert data[3:] == SOCKS5AuthMethod.USERNAME_PASSWORD


@pytest.mark.parametrize(
    "auth_method",
    [
        SOCKS5AuthMethod.NO_AUTH_REQUIRED,
        SOCKS5AuthMethod.USERNAME_PASSWORD,
        SOCKS5AuthMethod.GSSAPI,
    ],
)
def test_socks5_auth_reply_accepted(auth_method: SOCKS5AuthMethod) -> None:
    conn = SOCKS5Connection()
    request_methods = [
        SOCKS5AuthMethod.NO_AUTH_REQUIRED,
        SOCKS5AuthMethod.USERNAME_PASSWORD,
        SOCKS5AuthMethod.GSSAPI,
    ]

    conn.authenticate(request_methods)
    reply = conn.receive_data(b"\x05" + auth_method)

    assert reply == SOCKS5AuthReply(method=auth_method)


def test_socks5_auth_reply_no_acceptable_auth_method() -> None:
    conn = SOCKS5Connection()
    conn.authenticate([SOCKS5AuthMethod.USERNAME_PASSWORD])
    reply = conn.receive_data(b"\x05\xFF")

    assert reply == SOCKS5AuthReply(method=SOCKS5AuthMethod.NO_ACCEPTABLE_METHODS)
