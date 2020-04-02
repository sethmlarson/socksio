import pytest

from socksio import (
    ProtocolError,
    SOCKS4ARequest,
    SOCKS4Command,
    SOCKS4Connection,
    SOCKS4Reply,
    SOCKS4ReplyCode,
    SOCKS4Request,
    SOCKSError,
)


@pytest.mark.parametrize(
    "address,expected_address,expected_port",
    [
        (("127.0.0.1", 3080), b"\x7f\x00\x00\x01", 3080),
        (("127.0.0.1", "3080"), b"\x7f\x00\x00\x01", 3080),
        ("127.0.0.1:8080", b"\x7f\x00\x00\x01", 8080),
        ((b"127.0.0.1", 3080), b"\x7f\x00\x00\x01", 3080),
        ((b"127.0.0.1", b"3080"), b"\x7f\x00\x00\x01", 3080),
        (b"127.0.0.1:8080", b"\x7f\x00\x00\x01", 8080),
    ],
)
def test_socks4request_from_address(address, expected_address, expected_port) -> None:
    req = SOCKS4Request.from_address(SOCKS4Command.CONNECT, address, user_id=b"socksio")

    assert req.command == SOCKS4Command.CONNECT
    assert req.addr == expected_address
    assert req.port == expected_port
    assert req.user_id == b"socksio"


@pytest.mark.parametrize(
    "address,user_id",
    [
        (("::1", 3080), b"socksio"),  # IPV6
        ("localhost:3080", b"socksio"),  # Domain names
    ],
)
def test_socks4request_from_address_errors(address, user_id) -> None:
    with pytest.raises(SOCKSError):
        SOCKS4Request.from_address(
            command=SOCKS4Command.BIND, address=address, user_id=user_id
        )


def test_socks4request_from_address_dump_raises_if_no_user_id():
    req = SOCKS4Request.from_address(SOCKS4Command.CONNECT, "127.0.0.1:8080")

    with pytest.raises(SOCKSError):
        req.dumps()


@pytest.mark.parametrize(
    "address,expected_address,expected_port",
    [
        (("127.0.0.1", 3080), b"\x7f\x00\x00\x01", 3080),
        (("127.0.0.1", "3080"), b"\x7f\x00\x00\x01", 3080),
        ("127.0.0.1:8080", b"\x7f\x00\x00\x01", 8080),
        ((b"127.0.0.1", 3080), b"\x7f\x00\x00\x01", 3080),
        ((b"127.0.0.1", b"3080"), b"\x7f\x00\x00\x01", 3080),
        (b"127.0.0.1:8080", b"\x7f\x00\x00\x01", 8080),
    ],
)
def test_socks4arequest_from_address(address, expected_address, expected_port) -> None:
    req = SOCKS4ARequest.from_address(
        SOCKS4Command.CONNECT, address, user_id=b"socksio"
    )

    assert req.command == SOCKS4Command.CONNECT
    assert req.addr == expected_address
    assert req.port == expected_port
    assert req.user_id == b"socksio"


def test_socks4arequest_from_address_dump_raises_if_no_user_id():
    req = SOCKS4ARequest.from_address(SOCKS4Command.CONNECT, "127.0.0.1:8080")

    with pytest.raises(SOCKSError):
        req.dumps()


@pytest.mark.parametrize("command", [SOCKS4Command.BIND, SOCKS4Command.CONNECT])
def test_socks4_connection_request(command: SOCKS4Command) -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(command=command, address=("127.0.0.1", 8080))
    conn.send(request)

    data = conn.data_to_send()
    assert len(data) == 9 + 5
    assert data[0:1] == b"\x04"
    assert data[1:2] == command
    assert data[2:4] == (8080).to_bytes(2, byteorder="big")
    assert data[4:8] == b"\x7f\x00\x00\x01"
    assert data[8:13] == b"socks"
    assert data[13] == 0


@pytest.mark.parametrize("request_reply_code", list(SOCKS4ReplyCode))
def test_socks4_receive_data(request_reply_code: bytes) -> None:
    conn = SOCKS4Connection(user_id=b"socks")

    reply = conn.receive_data(
        b"".join(
            [
                b"\x00",
                request_reply_code,
                (8080).to_bytes(2, byteorder="big"),
                b"\x7f\x00\x00\x01",
            ]
        )
    )

    assert reply == SOCKS4Reply(
        reply_code=SOCKS4ReplyCode(request_reply_code), port=8080, addr="127.0.0.1"
    )


@pytest.mark.parametrize(
    "data",
    [
        b"\x00Z\x1f\x90\x7f\x00\x00",  # missing one byte
        b"\x0FZ\x1f\x90\x7f\x00\x00\x01",  # not starting with 0
        b"\x00\xFF\x1f\x90\x7f\x00\x00\x01",  # incorrect reply code
    ],
)
def test_socks4_receive_malformed_data(data: bytes) -> None:
    conn = SOCKS4Connection(user_id=b"socks")

    with pytest.raises(ProtocolError):
        conn.receive_data(data)


@pytest.mark.parametrize("command", [SOCKS4Command.BIND, SOCKS4Command.CONNECT])
def test_SOCKS4A_connection_request(command: SOCKS4Command) -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4ARequest.from_address(
        command=command, address=("proxy.example.com", 8080)
    )
    conn.send(request)

    data = conn.data_to_send()
    assert len(data) == 32
    assert data[0:1] == b"\x04"
    assert data[1:2] == command
    assert data[2:4] == (8080).to_bytes(2, byteorder="big")
    assert data[4:8] == b"\x00\x00\x00\xFF"
    assert data[8:14] == b"socks\x00"
    assert data[14:] == b"proxy.example.com\x00"
