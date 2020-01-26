import socket

from socksio import socks4


def send_data(sock, data):
    print("sending:", data)
    sock.sendall(data)


def receive_data(sock):
    data = sock.recv(1024)
    print("received:", data)
    return data


def main():
    # Assuming a running SOCKS4 proxy running in localhost:1080
    sock = socket.create_connection(("localhost", 1080))
    conn = socks4.SOCKS4Connection(user_id=b"socksio")

    # Request to connect to google.com port 80
    # SOCKS4 does not allow domain names, below is an IP for google.com
    request = socks4.SOCKS4Request.from_address(
        socks4.SOCKS4Command.CONNECT, ("216.58.204.78", 80)  # or "216.58.204.78:80"
    )
    conn.send(request)
    send_data(sock, conn.data_to_send())
    data = receive_data(sock)
    event = conn.receive_data(data)
    print("Request reply:", event)
    if event.reply_code != socks4.SOCKS4ReplyCode.REQUEST_GRANTED:
        raise Exception(
            "Server could not connect to remote host: {}".format(event.reply_code)
        )

    # Send an HTTP request to the connected proxy
    sock.sendall(b"GET / HTTP/1.1\r\nhost: google.com\r\n\r\n")
    data = receive_data(sock)
    print(data)


if __name__ == "__main__":
    main()
