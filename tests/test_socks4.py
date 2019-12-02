import pytest

from socksio import (
    ProtocolError,
    SOCKS4Command,
    SOCKS4Connection,
    SOCKS4Reply,
    SOCKS4ReplyCode,
    SOCKSError,
)


@pytest.mark.parametrize("command", [SOCKS4Command.BIND, SOCKS4Command.CONNECT])
def test_socks4_connection_request(command: SOCKS4Command) -> None:
    conn = SOCKS4Connection(user_id="socks".encode())

    conn.request(command=command, addr="127.0.0.1", port=8080)

    data = conn.data_to_send()
    assert len(data) == 9 + 5
    assert data[0:1] == b"\x04"
    assert data[1:2] == command
    assert data[2:4] == (8080).to_bytes(2, byteorder="big")
    assert data[4:8] == b"\x7f\x00\x00\x01"
    assert data[8:13] == "socks".encode()
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
    conn = SOCKS4Connection(user_id=b"socks", allow_domain_names=True)

    conn.request(command=command, addr="proxy.example.com", port=8080)

    data = conn.data_to_send()
    assert len(data) == 32
    assert data[0:1] == b"\x04"
    assert data[1:2] == command
    assert data[2:4] == (8080).to_bytes(2, byteorder="big")
    assert data[4:8] == b"\x00\x00\x00\xFF"
    assert data[8:14] == b"socks\x00"
    assert data[14:] == b"proxy.example.com\x00"


def test_SOCKS4_raises_if_passed_domain_name() -> None:
    conn = SOCKS4Connection(user_id=b"socks")

    with pytest.raises(SOCKSError):
        conn.request(command=SOCKS4Command.BIND, addr="proxy.example.com", port=8080)


def test_SOCKS4_does_not_support_ipv6() -> None:
    conn = SOCKS4Connection(user_id=b"socks")

    with pytest.raises(SOCKSError):
        conn.request(command=SOCKS4Command.BIND, addr="0:0:0:0:0:0:0:1", port=8080)
