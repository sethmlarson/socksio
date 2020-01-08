import enum
import typing

from .exceptions import ProtocolError
from .utils import AddressType, decode_address, encode_address


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

    @classmethod
    def from_atype(cls, atype: AddressType) -> "SOCKS5AType":
        if atype == AddressType.IPV4:
            return SOCKS5AType.IPV4_ADDRESS
        elif atype == AddressType.DN:
            return SOCKS5AType.DOMAIN_NAME
        elif atype == AddressType.IPV6:
            return SOCKS5AType.IPV6_ADDRESS
        raise ValueError(atype)


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
        return b"".join(
            [
                b"\x05",
                len(self.methods).to_bytes(1, byteorder="big"),
                b"".join(self.methods),
            ]
        )


class SOCKS5AuthReply(typing.NamedTuple):
    method: SOCKS5AuthMethod

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5AuthReply":
        if len(data) != 2:
            raise ProtocolError("Malformed reply")

        try:
            return cls(method=SOCKS5AuthMethod(data[1:2]))
        except ValueError as exc:
            raise ProtocolError("Malformed reply") from exc


class SOCKS5UsernamePasswordRequest(typing.NamedTuple):
    username: bytes
    password: bytes

    def dumps(self) -> bytes:
        return b"".join(
            [
                b"\x01",
                len(self.username).to_bytes(1, byteorder="big"),
                self.username,
                len(self.password).to_bytes(1, byteorder="big"),
                self.password,
            ]
        )


class SOCKS5UsernamePasswordReply(typing.NamedTuple):
    success: bool

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5UsernamePasswordReply":
        return cls(success=data == b"\x01\x00")


class SOCKS5Request(typing.NamedTuple):
    command: SOCKS5Command
    atype: SOCKS5AType
    addr: bytes
    port: int

    def dumps(self) -> bytes:
        return b"".join(
            [
                b"\x05",
                self.command,
                b"\x00",
                self.atype,
                self.packed_addr,
                (self.port).to_bytes(2, byteorder="big"),
            ]
        )

    @property
    def packed_addr(self) -> bytes:
        if self.atype == SOCKS5AType.IPV4_ADDRESS:
            assert len(self.addr) == 4
            return self.addr
        elif self.atype == SOCKS5AType.IPV6_ADDRESS:
            assert len(self.addr) == 16
            return self.addr
        else:
            length = len(self.addr)
            return length.to_bytes(1, byteorder="big") + self.addr


class SOCKS5Reply(typing.NamedTuple):
    reply_code: SOCKS5ReplyCode
    atype: SOCKS5AType
    addr: str
    port: int

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5Reply":
        if data[0:1] != b"\x05":
            raise ProtocolError("Malformed reply")

        try:
            atype = SOCKS5AType(data[3:4])

            return cls(
                reply_code=SOCKS5ReplyCode(data[1:2]),
                atype=atype,
                addr=decode_address(AddressType.from_socks5_atype(atype), data[4:-2]),
                port=int.from_bytes(data[-2:], byteorder="big"),
            )
        except ValueError as exc:
            raise ProtocolError("Malformed reply") from exc


class SOCKS5Datagram(typing.NamedTuple):
    atype: SOCKS5AType
    addr: bytes
    port: int
    data: bytes

    fragment: int
    last_fragment: bool

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5Datagram":
        raise NotImplementedError()  # pragma: nocover

    def dumps(self) -> bytes:
        raise NotImplementedError()  # pragma: nocover


class SOCKS5State(enum.IntEnum):
    CLIENT_AUTH_REQUIRED = 1
    SERVER_AUTH_REPLY = 2
    CLIENT_AUTHENTICATED = 3
    TUNNEL_READY = 4
    CLIENT_WAITING_FOR_USERNAME_PASSWORD = 5
    SERVER_VERIFY_USERNAME_PASSWORD = 6
    MUST_CLOSE = 7


class SOCKS5Connection:
    def __init__(self) -> None:
        self._data_to_send = bytearray()
        self._received_data = bytearray()
        self._state = SOCKS5State.CLIENT_AUTH_REQUIRED

    @property
    def state(self) -> SOCKS5State:
        return self._state

    def authenticate(self, methods: typing.List[SOCKS5AuthMethod]) -> None:
        auth_request = SOCKS5AuthRequest(methods)
        self._data_to_send += auth_request.dumps()
        self._state = SOCKS5State.SERVER_AUTH_REPLY

    def authenticate_username_password(self, username: bytes, password: bytes) -> None:
        if self._state != SOCKS5State.CLIENT_WAITING_FOR_USERNAME_PASSWORD:
            raise ProtocolError("Not currently waiting for username and password")
        self._state = SOCKS5State.SERVER_VERIFY_USERNAME_PASSWORD
        request = SOCKS5UsernamePasswordRequest(username=username, password=password)
        self._data_to_send += request.dumps()

    def request(self, command: SOCKS5Command, addr: str, port: int) -> None:
        if self._state < SOCKS5State.CLIENT_AUTHENTICATED:
            raise ProtocolError(
                "SOCKS5 connections must be authenticated before sending a request"
            )
        atype, encoded_addr = encode_address(addr)
        request = SOCKS5Request(
            command=command,
            atype=SOCKS5AType.from_atype(atype),
            addr=encoded_addr,
            port=port,
        )
        self._data_to_send += request.dumps()

    def receive_data(
        self, data: bytes
    ) -> typing.Union[SOCKS5AuthReply, SOCKS5Reply, SOCKS5UsernamePasswordReply]:
        if self._state == SOCKS5State.SERVER_AUTH_REPLY:
            auth_reply = SOCKS5AuthReply.loads(data)
            if auth_reply.method == SOCKS5AuthMethod.USERNAME_PASSWORD:
                self._state = SOCKS5State.CLIENT_WAITING_FOR_USERNAME_PASSWORD
            elif auth_reply.method == SOCKS5AuthMethod.NO_AUTH_REQUIRED:
                self._state = SOCKS5State.CLIENT_AUTHENTICATED
            return auth_reply

        if self._state == SOCKS5State.SERVER_VERIFY_USERNAME_PASSWORD:
            username_password_reply = SOCKS5UsernamePasswordReply.loads(data)
            if username_password_reply.success:
                self._state = SOCKS5State.CLIENT_AUTHENTICATED
            else:
                self._state = SOCKS5State.MUST_CLOSE
            return username_password_reply

        if self._state == SOCKS5State.CLIENT_AUTHENTICATED:
            reply = SOCKS5Reply.loads(data)
            if reply.reply_code == SOCKS5ReplyCode.SUCCEEDED:
                self._state = SOCKS5State.TUNNEL_READY
            else:
                self._state = SOCKS5State.MUST_CLOSE

            return reply

        raise NotImplementedError()  # pragma: nocover

    def data_to_send(self) -> bytes:
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data
