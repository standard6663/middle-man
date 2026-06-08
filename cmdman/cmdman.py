
import random
import socket
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .cmdpkt import RawPacket, CommandPacket, Command, ExchangeRandomData
from .crypto import hash_sha256, hmac_sha256, calc_nonce

MAX_PACKET_SIZE = 4096  # 最大数据包大小


class CommandManager:
    def __init__(self, secret: str | bytes, role: str, host: str, port: int):
        if isinstance(secret, str):
            secret = secret.encode('utf-8')
        self.mk = hash_sha256(secret)
        self.encryption = False  # 加密标志，当前通信是否加密
        self.role = role  # 角色，'gateway' 或 'midman'
        self.host = host
        self.port = port
        self.socket: socket.socket = None

        self.gateway_random = None
        self.midman_random = None

        self.sk = None
        self.iv = None
        self.ctr = None

        g_state_machine = {
            'g_init': {
                '': (self.g_init, 'g_exchange_rand'),
                'err': (lambda _: _, 'g_init')
            },
            'g_exchange_rand': {
                '': (self.g_exchange_rand, 'g_start_enc'),
                'err':  (lambda _: _, 'g_init')
            },
            'g_start_enc': {
                '': (self.g_start_enc, 'g_finished'),
                'err':  (lambda _: _, 'g_init')
            },
        }

        m_state_machine = {
            'm_init': {
                '': (self.m_init, 'm_exchange_rand'),
                'err':  (lambda _: _, 'm_init')
            },
            'm_exchange_rand': {
                '': (self.m_exchange_rand, 'm_start_enc'),
                'err':  (lambda _: _, 'm_init')
            },
            'm_start_enc': {
                '': (self.m_start_enc, 'm_finished'),
                'err':  (lambda _: _, 'm_init')
            },
        }

        if self.role == 'gateway':
            self.state_machine = g_state_machine
            self.state = 'g_init'
        elif self.role == 'midman':
            self.state_machine = m_state_machine
            self.state = 'm_init'
        else:
            raise ValueError("Invalid role. Must be 'gateway' or 'midman'.")

        self.process_event()

    def send(self, cmd_pkt: CommandPacket):
        raw_packet: RawPacket = CommandPacket.to_raw_packet(cmd_pkt)
        if self.encryption:
            raw_packet.raw = self.encrypt(raw_packet.raw)
        self.socket.send(raw_packet.to_bytes())

    def receive(self) -> CommandPacket:
        raw = self.socket.recv(CommandPacket.HEADER_SIZE)
        if not raw:
            raise ValueError("接收数据失败")
        _, length = CommandPacket.parse_only_header(raw)
        if length:
            raw += self.socket.recv(length)
        if self.encryption:
            raw = self.decrypt(raw)
        cmd_pkt = CommandPacket.from_bytes(raw)
        return cmd_pkt

    def start_encryption(self):
        salt = self.gateway_random + self.midman_random
        mac = hmac_sha256(self.mk, salt)
        self.sk = mac[0:16]
        self.iv = mac[16:28]
        self.ctr = 0
        self.encryption = True

    def encrypt(self, data: bytes) -> bytes:
        n = calc_nonce(self.iv, struct.pack('>Q', self.ctr))
        self.ctr += 1
        aesgcm = AESGCM(self.sk)
        return aesgcm.encrypt(n, data, None)

    def decrypt(self, data: bytes) -> bytes:
        n = calc_nonce(self.iv, struct.pack('>Q', self.ctr))
        self.ctr += 1
        aesgcm = AESGCM(self.sk)
        ciphertext = data[5:]
        return data[0:5] + aesgcm.decrypt(n, ciphertext, None)

    def process_event(self, event: str = ''):
        if 'finished' in self.state:
            return
        if event not in self.state_machine[self.state]:
            raise ValueError(f"Invalid event '{event}' for state '{self.state}'")

        action, next_state = self.state_machine[self.state][event]
        self.state = next_state
        action()

    def g_init(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.process_event()

    def g_exchange_rand(self):
        # 实现随机数交换逻辑
        self.gateway_random = bytes(random.choices(range(256), k=16))
        self.gateway_random = b'\x01' * 16
        cmd_pkt = CommandPacket(Command.EXCHANGE_RANDOM, ExchangeRandomData(self.gateway_random))
        self.send(cmd_pkt) 
        # 错误处理, 调用 self.process_event('err')
        receive_cmd_pkt = self.receive()
        if receive_cmd_pkt.command_code != Command.EXCHANGE_RANDOM:
            self.process_event('err')
        self.midman_random = receive_cmd_pkt.data_obj.to_bytes()
        self.process_event()

    def g_start_enc(self):
        self.start_encryption()
        self.process_event()
    
    def m_init(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        self.socket, addr = self.socket.accept()
        self.process_event()
    
    def m_exchange_rand(self):
        # 实现随机数交换逻辑
        receive_cmd_pkt = self.receive()
        if receive_cmd_pkt.command_code != Command.EXCHANGE_RANDOM:
            self.process_event('err')
        self.gateway_random = receive_cmd_pkt.data_obj.to_bytes()
        self.midman_random = bytes(random.choices(range(256), k=16))
        cmd_pkt = CommandPacket(Command.EXCHANGE_RANDOM, ExchangeRandomData(self.midman_random))
        self.send(cmd_pkt)
        self.process_event()
    
    def m_start_enc(self):
        self.start_encryption()
        self.process_event()
    
