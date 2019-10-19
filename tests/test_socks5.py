import pytest

from socks import (
    ProtocolError,
    SOCKS5AuthMethod,
    SOCKS5AuthReply,
    SOCKS5Command,
    SOCKS5Connection,
    SOCKS5Reply,
    SOCKS5ReplyCode,
    SOCKS5AType,
)
from socks.socks5 import SOCKS5State


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


@pytest.mark.parametrize(
    "data", [b"\x05", b"\x05\x10"]  # missing method byte , incorrect method value
)
def test_socks5_auth_reply_malformed(data: bytes) -> None:
    conn = SOCKS5Connection()
    conn.authenticate([SOCKS5AuthMethod.USERNAME_PASSWORD])
    with pytest.raises(ProtocolError):
        conn.receive_data(data)


def test_socks5_auth_username_password_success() -> None:
    conn = SOCKS5Connection()
    conn.authenticate([SOCKS5AuthMethod.USERNAME_PASSWORD])
    conn.data_to_send()
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.USERNAME_PASSWORD)
    conn.authenticate_username_password(b"username", b"password")
    assert conn.data_to_send() == b"\x01\x08username\x08password"
    conn.receive_data(b"\x00")
    assert conn._state == SOCKS5State.CLIENT_AUTHENTICATED


def test_socks5_auth_username_password_fail() -> None:
    conn = SOCKS5Connection()
    conn.authenticate([SOCKS5AuthMethod.USERNAME_PASSWORD])
    conn.data_to_send()
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.USERNAME_PASSWORD)
    conn.authenticate_username_password(b"username", b"password")
    assert conn.data_to_send() == b"\x01\x08username\x08password"
    conn.receive_data(b"\x01")
    assert conn._state == SOCKS5State.MUST_CLOSE


def test_socks5_request_require_authentication() -> None:
    conn = SOCKS5Connection()
    with pytest.raises(ProtocolError):
        conn.request(SOCKS5Command.CONNECT, addr="127.0.0.1", port=1080)


@pytest.fixture
def authenticated_conn() -> SOCKS5Connection:
    conn = SOCKS5Connection()
    conn.authenticate([SOCKS5AuthMethod.USERNAME_PASSWORD])
    conn.data_to_send()
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.USERNAME_PASSWORD)
    conn.authenticate_username_password(b"username", b"password")
    conn.data_to_send()
    conn.receive_data(b"\x00")
    return conn


@pytest.mark.parametrize("command", (SOCKS5Command.CONNECT, SOCKS5Command.BIND))
def test_socks5_request_ipv4(
    authenticated_conn: SOCKS5Connection, command: SOCKS5Command
) -> None:
    authenticated_conn.request(command, addr="127.0.0.1", port=1080)

    data = authenticated_conn.data_to_send()

    assert len(data) == 10
    assert data[0:1] == b"\x05"
    assert data[1:2] == command
    assert data[2:3] == b"\x00"
    assert data[3:4] == b"\x01"
    assert data[4:8] == b"\x7f\x00\x00\x01"
    assert data[8:] == (1080).to_bytes(2, byteorder="big")


@pytest.mark.parametrize("command", (SOCKS5Command.CONNECT, SOCKS5Command.BIND))
def test_socks5_request_domain_name(
    authenticated_conn: SOCKS5Connection, command: SOCKS5Command
) -> None:
    authenticated_conn.request(command, addr="localhost", port=1080)

    data = authenticated_conn.data_to_send()

    assert len(data) == 15
    assert data[0:1] == b"\x05"
    assert data[1:2] == command
    assert data[2:3] == b"\x00"
    assert data[3:4] == b"\x03"
    assert data[4:13] == b"localhost"
    assert data[13:] == (1080).to_bytes(2, byteorder="big")


@pytest.mark.parametrize("command", (SOCKS5Command.CONNECT, SOCKS5Command.BIND))
def test_socks5_request_ipv6(
    authenticated_conn: SOCKS5Connection, command: SOCKS5Command
) -> None:
    authenticated_conn.request(command, addr="0:0:0:0:0:0:0:1", port=1080)

    data = authenticated_conn.data_to_send()

    assert len(data) == 22
    assert data[0:1] == b"\x05"
    assert data[1:2] == command
    assert data[2:3] == b"\x00"
    assert data[3:4] == b"\x04"
    assert (
        data[4:20]
        == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
    )
    assert data[20:] == (1080).to_bytes(2, byteorder="big")


def test_socks5_reply_success(authenticated_conn: SOCKS5Connection) -> None:
    reply = authenticated_conn.receive_data(
        b"".join(
            [
                b"\x05",  # protocol version
                b"\x00",  # reply
                b"\x00",  # reserved
                b"\x01",  # atype
                b"\x7f\x00\x00\x01",  # addr
                (1080).to_bytes(2, byteorder="big"),  # port
            ]
        )
    )

    assert reply == SOCKS5Reply(
        reply_code=SOCKS5ReplyCode.SUCCEEDED,
        atype=SOCKS5AType.IPV4_ADDRESS,
        addr="127.0.0.1",
        port=1080,
    )
