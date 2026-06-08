import struct
from enum import IntEnum


class Command(IntEnum):
    EXCHANGE_RANDOM = 0x01
    UPDATE_DATA = 0x02
    REQUEST_DATA = 0x03
    START = 0x04
    STOP = 0x05
    ERROR = 0xFF


ENCRYPTION_CMD = [
    Command.UPDATE_DATA,
    Command.REQUEST_DATA,
    Command.START,
    Command.STOP
]


class DateType(IntEnum):
    CERTS = 0x01
    PORT = 0x02
    DATABSE = 0x03


class RawData:
    def __init__(self, data: bytes):
        self.data = data

    def to_bytes(self):
        return self.data

    @classmethod
    def from_bytes(cls, data: bytes):
        return cls(data)

    def __repr__(self):
        return f"<RawData {self.data.hex()}>"


class ExchangeRandomData:
    def __init__(self, random_bytes: bytes):
        self.random_bytes = random_bytes

    def to_bytes(self):
        return self.random_bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) != 16:
            raise ValueError("ExchangeRandom 长度必须是16字节")
        return cls(data)

    def __repr__(self):
        return f"<ExchangeRandom random={self.random_bytes.hex()}>"


class UpdateData:
    def __init__(self, date_type: DateType, data: bytes):
        self.date_type = date_type
        self.data = data

    def to_bytes(self):
        combined = bytes([self.date_type]) + self.data
        pad_length = (16 - (len(combined) % 16)) % 16
        return combined + bytes([0x01] * pad_length)

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < 1:
            raise ValueError("数据太短")

        date_type = DateType(data[0])
        data_part = data[1:]

        # 去除填充的0x01
        last_non_pad = len(data_part)
        while last_non_pad > 0 and data_part[last_non_pad - 1] == 0x01:
            last_non_pad -= 1
        actual_data = data_part[:last_non_pad]

        # 验证固定长度类型
        if date_type == DateType.PORT and len(actual_data) != 2:
            raise ValueError("PROXY_PORT 数据长度必须为2字节")
        
        return cls(date_type, actual_data)

    def __repr__(self):
        return f"<UpdateData type={self.date_type}, data={self.data.hex()}>"


class RequestData:
    def __init__(self, date_type: DateType):
        self.date_type = date_type

    def to_bytes(self):
        return bytes([self.date_type]) + bytes([0x01] * 15)

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) != 16 or data[1:] != bytes([0x01]*15):
            raise ValueError("无效的RequestData格式")
        return cls(DateType(data[0]))

    def __repr__(self):
        return f"<RequestData type={self.date_type}>"


class StartData:
    def to_bytes(self):
        return b"START" + bytes([0x01] * 11)

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) != 16 or data[:5] != b"START" or data[5:] != bytes([0x01]*11):
            raise ValueError("无效的StartData格式")
        return cls()

    def __repr__(self):
        return "<StartData>"


class StopData:
    def to_bytes(self):
        return b"STOP" + bytes([0x01] * 12)

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) != 16 or data[:4] != b"STOP" or data[4:] != bytes([0x01]*12):
            raise ValueError("无效的StopData格式")
        return cls()

    def __repr__(self):
        return "<StopData>"


class ErrorData:
    def __init__(self, message: bytes):
        self.message = message

    def to_bytes(self):
        return self.message

    @classmethod
    def from_bytes(cls, data: bytes):
        return cls(data)

    def __repr__(self):
        return f"<ErrorData message={self.message.decode()}>"


DATA_PARSERS = {
    Command.EXCHANGE_RANDOM: ExchangeRandomData,
    Command.UPDATE_DATA: UpdateData,
    Command.REQUEST_DATA: RequestData,
    Command.START: StartData,
    Command.STOP: StopData,
    Command.ERROR: ErrorData,
}


class RawPacket:
    HEADER_FORMAT = '<BI'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, command_code: int, raw=None):
        self.command_code = command_code
        self.raw: bytes = raw

    def to_bytes(self) -> bytes:
        raw_data = self.raw if self.raw else b''
        header = struct.pack(self.HEADER_FORMAT, self.command_code, len(raw_data))
        return header + raw_data

    @classmethod
    def from_bytes(cls, raw: bytes):
        if len(raw) < cls.HEADER_SIZE:
            raise ValueError("数据太短")

        command_code, length = struct.unpack(cls.HEADER_FORMAT, raw[:cls.HEADER_SIZE])
        data = raw[cls.HEADER_SIZE:cls.HEADER_SIZE + length]

        return cls(command_code, data)

    def __repr__(self):
        return f"<RawPacket command_code={self.command_code}, raw={self.raw.hex()}>"


class CommandPacket:
    HEADER_FORMAT = '<BI'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, command_code: int, data_obj=None):
        self.command_code = command_code
        self.data_obj = data_obj

    def to_bytes(self) -> bytes:
        raw_data = self.data_obj.to_bytes() if self.data_obj else b''
        header = struct.pack(self.HEADER_FORMAT, self.command_code, len(raw_data))
        return header + raw_data
    
    @classmethod
    def parse_only_header(cls, raw: bytes):
        if len(raw) < cls.HEADER_SIZE:
            return None, None
        command_code, length = struct.unpack(cls.HEADER_FORMAT, raw[:cls.HEADER_SIZE])
        return command_code, length

    @classmethod
    def from_bytes(cls, raw: bytes):
        if len(raw) < cls.HEADER_SIZE:
            raise ValueError("数据太短")

        command_code, length = struct.unpack(cls.HEADER_FORMAT, raw[:cls.HEADER_SIZE])
        data = raw[cls.HEADER_SIZE:cls.HEADER_SIZE + length]

        data_cls = DATA_PARSERS.get(command_code, RawData)
        data_obj = data_cls.from_bytes(data)
        return cls(command_code, data_obj)

    @classmethod
    def from_raw_packet(cls, raw_packet: RawPacket):
        command_code = raw_packet.command_code
        data_cls = DATA_PARSERS.get(command_code, RawData)
        data_obj = data_cls.from_bytes(raw_packet.raw)
        return cls(command_code, data_obj)

    @classmethod
    def to_raw_packet(cls, command_packet: 'CommandPacket'):
        raw_data = command_packet.data_obj.to_bytes() if command_packet.data_obj else b''
        return RawPacket(command_packet.command_code, raw_data)

    def __repr__(self):
        return f"<CommandPacket command_code={self.command_code}, data={self.data_obj}>"
