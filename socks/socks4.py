import enum
import typing

from .exceptions import ProtocolError, SOCKSError
from .utils import AddressType, decode_address, encode_address


class SOCKS4ReplyCode(bytes, enum.Enum):
    REQUEST_GRANTED = b"\x5A"
    REQUEST_REJECTED_OR_FAILED = b"\x5B"
    CONNECTION_FAILED = b"\x5C"
    AUTHENTICATION_FAILED = b"\x5D"


class SOCKS4Command(bytes, enum.Enum):
    CONNECT = b"\x01"
    BIND = b"\x02"


class SOCKS4Request(typing.NamedTuple):
    command: SOCKS4Command
    port: int
    addr: bytes
    user_id: bytes

    def dumps(self) -> bytes:
        return b"".join(
            [
                b"\x04",
                self.command,
                (self.port).to_bytes(2, byteorder="big"),
                self.addr,
                self.user_id,
                b"\x00",
            ]
        )


class SOCKS4ARequest(typing.NamedTuple):
    command: SOCKS4Command
    port: int
    addr: str
    user_id: bytes

    def dumps(self) -> bytes:
        raise NotImplementedError()


class SOCKS4Reply(typing.NamedTuple):
    reply_code: SOCKS4ReplyCode
    port: int
    addr: typing.Optional[str]

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS4Reply":
        if len(data) != 8 or data[0:1] != b"\x00":
            raise ProtocolError("Malformed reply")
        return cls(
            reply_code=SOCKS4ReplyCode(data[1:2]),
            port=int.from_bytes(data[2:4], byteorder="big"),
            addr=decode_address(AddressType.IPV4, data[4:8]),
        )


class SOCKS4Connection:
    def __init__(self, user_id: bytes = None, allow_domain_names: bool = False):
        self.user_id = user_id

        # Set to 'True' when using 'socks4a://'
        self.allow_domain_names = allow_domain_names

        self._data_to_send = bytearray()
        self._received_data = bytearray()

    def request(
        self,
        command: SOCKS4Command,
        addr: str,
        port: int,
        user_id: typing.Optional[bytes] = None,
    ) -> None:
        if user_id is None:
            user_id = self.user_id or b""

        address_type, encoded_addr = encode_address(addr)
        if address_type == AddressType.IPV6:
            raise SOCKSError("IPv6 addresses not supported by SOCKS4")
        elif address_type == AddressType.DN and not self.allow_domain_names:
            raise SOCKSError("Domain names only supported by SOCKS4A")

        request = SOCKS4Request(command, port, encoded_addr, user_id)
        self._data_to_send += request.dumps()

    def receive_data(self, data: bytes) -> SOCKS4Reply:
        self._received_data += data
        return SOCKS4Reply.loads(bytes(self._received_data))

    def data_to_send(self) -> bytes:
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data
