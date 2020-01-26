import socket

from socksio import socks5


def send_data(sock, data):
    print("Sending:", data)
    sock.sendall(data)


def receive_data(sock):
    data = sock.recv(1024)
    print("Received:", data)
    return data


def main():
    # Assuming a running SOCKS5 proxy running in localhost:1080
    sock = socket.create_connection(("localhost", 1080))
    conn = socks5.SOCKS5Connection()

    # The proxy may return any of these options
    request = socks5.SOCKS5AuthMethodsRequest(
        [
            socks5.SOCKS5AuthMethod.NO_AUTH_REQUIRED,
            socks5.SOCKS5AuthMethod.USERNAME_PASSWORD,
        ]
    )
    conn.send(request)
    send_data(sock, conn.data_to_send())
    data = receive_data(sock)
    event = conn.receive_data(data)
    print("Auth reply:", event)

    # If the proxy requires username/password you'll have to edit them below
    if event.method == socks5.SOCKS5AuthMethod.USERNAME_PASSWORD:
        request = socks5.SOCKS5UsernamePasswordRequest(b"socksio", b"socksio")
        conn.send(request)
        send_data(sock, conn.data_to_send())
        data = receive_data(sock)
        event = conn.receive_data(data)
        print("User/pass auth reply:", event)
        if not event.success:
            raise Exception("Invalid username/password")

    # Request to connect to google.com port 80
    request = socks5.SOCKS5CommandRequest.from_address(
        socks5.SOCKS5Command.CONNECT, ("google.com", 80)
    )
    conn.send(request)
    send_data(sock, conn.data_to_send())
    data = receive_data(sock)
    event = conn.receive_data(data)
    print("Request reply:", event)

    if event.reply_code != socks5.SOCKS5ReplyCode.SUCCEEDED:
        raise Exception(
            "Server could not connect to remote host: {}".format(event.reply_code)
        )

    # Send an HTTP request to the connected proxy
    sock.sendall(b"GET / HTTP/1.1\r\nhost: google.com\r\n\r\n")
    data = receive_data(sock)
    print("Response", data)


if __name__ == "__main__":
    main()
