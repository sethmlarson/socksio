import pytest

from socks import (
    ProtocolError,
    SOCKS4Command,
    SOCKS4Connection,
    SOCKS4Reply,
    SOCKS4ReplyCode,
)


@pytest.mark.parametrize("command", [SOCKS4Command.BIND, SOCKS4Command.CONNECT])
def test_socks4_connection_request_no_user_id(command: SOCKS4Command) -> None:
    conn = SOCKS4Connection(user_id=None)

    conn.request(command=command, addr="127.0.0.1", port=8080)

    data = conn.data_to_send()
    assert len(data) == 9
    assert data[0:1] == b"\x04"
    assert data[1:2] == command
    assert data[2:4] == (8080).to_bytes(2, byteorder="big")
    assert data[4:8] == b"\x7f\x00\x00\x01"
    assert data[8] == 0


@pytest.mark.parametrize("command", [SOCKS4Command.BIND, SOCKS4Command.CONNECT])
def test_socks4_connection_request_user_id(command: SOCKS4Command) -> None:
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


@pytest.mark.parametrize("request_reply_code", [value for value in SOCKS4ReplyCode])
def test_socks4_receive_data(request_reply_code: bytes) -> None:
    conn = SOCKS4Connection()

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


def test_socks4_receive_malformed_data() -> None:
    conn = SOCKS4Connection()

    with pytest.raises(ProtocolError):
        conn.receive_data(b"\x00Z\x1f\x90\x7f\x00\x00")  # missing one byte
