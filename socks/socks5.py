import enum
import typing

from .utils import AddressType, encode_address


class SOCKS5AuthMethod(bytes, enum.Enum):
    NO_AUTH_REQUIRED = b"\x00"
    GSSAPI = b"\x01"
    USERNAME_PASSWORD = b"\x02"
    NO_ACCEPTABLE_METHODS = b"\xFF"


class SOCKS5Command(bytes, enum.Enum):
    CONNECT = b"\x01"
    BIND = b"\x02"
    UDP_ASSOCIATE = b"\x03"


class SOCKS5AType(bytes, enum.Enum):
    IPV4_ADDRESS = b"\x01"
    DOMAIN_NAME = b"\x03"
    IPV6_ADDRESS = b"\x04"


class SOCKS5ReplyCode(bytes, enum.Enum):
    SUCCEEDED = b"\x00"
    GENERAL_SERVER_FAILURE = b"\x01"
    CONNECTION_NOT_ALLOWED_BY_RULESET = b"\x02"
    NETWORK_UNREACHABLE = b"\x03"
    HOST_UNREACHABLE = b"\x04"
    CONNECTION_REFUSED = b"\x05"
    TTL_EXPIRED = b"\x06"
    COMMAND_NOT_SUPPORTED = b"\x07"
    ADDRESS_TYPE_NOT_SUPPORTED = b"\x08"


class SOCKS5AuthRequest(typing.NamedTuple):
    methods: typing.List[SOCKS5AuthMethod]

    def dumps(self) -> bytes:
        raise NotImplementedError()


class SOCKS5AuthReply(typing.NamedTuple):
    method: SOCKS5AuthMethod

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5AuthReply":
        raise NotImplementedError()


class SOCKS5Request(typing.NamedTuple):
    command: SOCKS5Command
    atype: SOCKS5AType
    addr: bytes
    port: int

    def dumps(self) -> bytes:
        raise NotImplementedError()


class SOCKS5Reply(typing.NamedTuple):
    reply_code: SOCKS5ReplyCode
    atype: SOCKS5AType
    addr: bytes
    port: int

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5Reply":
        raise NotImplementedError()


class SOCKS5Datagram(typing.NamedTuple):
    atype: SOCKS5AType
    addr: bytes
    port: int
    data: bytes

    fragment: int
    last_fragment: bool

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5Datagram":
        raise NotImplementedError()

    def dumps(self) -> bytes:
        raise NotImplementedError()


class SOCKS5Connection:
    def __init__(self) -> None:
        self._data_to_send = bytearray()
        self._received_data = bytearray()

    def authenticate(self, methods: typing.List[SOCKS5AuthMethod]) -> None:
        raise NotImplementedError()

    def request(self, command: SOCKS5Command, addr: str, port: int) -> None:
        address_type, encoded_addr = encode_address(addr)
        if address_type == AddressType.IPV4:
            atype = SOCKS5AType.IPV4_ADDRESS
        elif address_type == AddressType.IPV6:
            atype = SOCKS5AType.IPV6_ADDRESS
        else:
            assert address_type == AddressType.DN
            atype = SOCKS5AType.DOMAIN_NAME

        request = SOCKS5Request(
            command=command, atype=atype, addr=encoded_addr, port=port
        )
        self._data_to_send += request.dumps()

    def receive_data(
        self, data: bytes
    ) -> typing.List[typing.Union[SOCKS5AuthReply, SOCKS5Reply]]:
        self._received_data += data
        raise NotImplementedError()

    def data_to_send(self) -> bytes:
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data
