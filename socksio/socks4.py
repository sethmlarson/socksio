import enum
import typing

from .exceptions import ProtocolError, SOCKSError
from .utils import (
    AddressType,
    decode_address,
    encode_address,
    split_address_port_from_string,
)


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
    user_id: typing.Optional[bytes] = None

    @classmethod
    def from_address(
        cls,
        command: SOCKS4Command,
        address: typing.Union[str, typing.Tuple[str, int]],
        user_id: typing.Optional[bytes] = None,
    ) -> "SOCKS4Request":
        if isinstance(address, str):
            address, port = split_address_port_from_string(address)
        else:
            address, port = address
            if isinstance(port, str):
                port = int(port)

        atype, encoded_addr = encode_address(address)
        if atype != AddressType.IPV4:
            raise SOCKSError(
                "IPv6 addresses and domain names are not supported by SOCKS4"
            )
        return cls(command=command, addr=encoded_addr, port=port, user_id=user_id)

    def dumps(self, user_id: typing.Optional[bytes] = None) -> bytes:
        user_id = user_id or self.user_id
        if user_id is None:
            raise SOCKSError("SOCKS4 requires a user_id, none was specified")

        return b"".join(
            [
                b"\x04",
                self.command,
                (self.port).to_bytes(2, byteorder="big"),
                self.addr,
                user_id,
                b"\x00",
            ]
        )


class SOCKS4ARequest(typing.NamedTuple):
    command: SOCKS4Command
    port: int
    addr: bytes
    user_id: typing.Optional[bytes] = None

    @classmethod
    def from_address(
        cls,
        command: SOCKS4Command,
        address: typing.Union[str, typing.Tuple[str, int]],
        user_id: typing.Optional[bytes] = None,
    ) -> "SOCKS4ARequest":
        if isinstance(address, str):
            address, port = split_address_port_from_string(address)
        else:
            address, port = address
            if isinstance(port, str):
                port = int(port)

        atype, encoded_addr = encode_address(address)
        return cls(command=command, addr=encoded_addr, port=port, user_id=user_id)

    def dumps(self, user_id: typing.Optional[bytes] = None) -> bytes:
        user_id = user_id or self.user_id
        if user_id is None:
            raise SOCKSError("SOCKS4 requires a user_id, none was specified")

        return b"".join(
            [
                b"\x04",
                self.command,
                (self.port).to_bytes(2, byteorder="big"),
                b"\x00\x00\x00\xFF",  # arbitrary final non-zero byte
                user_id,
                b"\x00",
                self.addr,
                b"\x00",
            ]
        )


class SOCKS4Reply(typing.NamedTuple):
    reply_code: SOCKS4ReplyCode
    port: int
    addr: typing.Optional[str]

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS4Reply":
        if len(data) != 8 or data[0:1] != b"\x00":
            raise ProtocolError("Malformed reply")

        try:
            return cls(
                reply_code=SOCKS4ReplyCode(data[1:2]),
                port=int.from_bytes(data[2:4], byteorder="big"),
                addr=decode_address(AddressType.IPV4, data[4:8]),
            )
        except ValueError as exc:
            raise ProtocolError("Malformed reply") from exc


class SOCKS4Connection:
    def __init__(self, user_id: bytes):
        self.user_id = user_id

        self._data_to_send = bytearray()
        self._received_data = bytearray()

    def send(self, request: typing.Union[SOCKS4Request, SOCKS4ARequest]) -> None:
        user_id = request.user_id or self.user_id
        self._data_to_send += request.dumps(user_id=user_id)

    def receive_data(self, data: bytes) -> SOCKS4Reply:
        self._received_data += data
        return SOCKS4Reply.loads(bytes(self._received_data))

    def data_to_send(self) -> bytes:
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data
