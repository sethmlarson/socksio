from socks import SOCKS4Connection, SOCKS4Command


def test_socks4_connection_request_no_user_id() -> None:
    conn = SOCKS4Connection(user_id=None)

    conn.request(command=SOCKS4Command.CONNECT, addr="127.0.0.1", port=8080)

    data = conn.data_to_send()
    assert len(data) == 9
    assert data[0:1] == b"\x04"
    assert data[1:2] == SOCKS4Command.CONNECT
    assert data[2:4] == (8080).to_bytes(2, byteorder="big")
    assert data[4:8] == b"\x7f\x00\x00\x01"
    assert data[8] == 0


def test_socks4_connection_request_user_id() -> None:
    conn = SOCKS4Connection(user_id="socks".encode())

    conn.request(command=SOCKS4Command.CONNECT, addr="127.0.0.1", port=8080)

    data = conn.data_to_send()
    assert len(data) == 9 + 5
    assert data[0:1] == b"\x04"
    assert data[1:2] == SOCKS4Command.CONNECT
    assert data[2:4] == (8080).to_bytes(2, byteorder="big")
    assert data[4:8] == b"\x7f\x00\x00\x01"
    assert data[8:13] == "socks".encode()
    assert data[13] == 0
