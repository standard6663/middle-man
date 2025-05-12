from __future__ import annotations
import base64
import threading
from midman.context import Context
from midman.pipe import PipeReader
from scapy.layers.tls.all import TLS, TLSApplicationData
from midman.prototype import PacketType
from midman.database import TrafficDatabase
# from midman.database import TrafficDatabaseDebug as TrafficDatabase


class Address:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    @classmethod
    def from_tuple(cls, ip_port_tuple):
        ip, port = ip_port_tuple
        return cls(ip, port)

    def __str__(self):
        return f"{self.ip}:{self.port}"

    def __eq__(self, value: Address | tuple | list):
        if isinstance(value, Address):
            return self.ip == value.ip and self.port == value.port
        elif isinstance(value, tuple) or isinstance(value, list):
            return self.ip == value[0] and self.port == value[1]
        return False

    def __ne__(self, value):
        return not self.__eq__(value)


class Connection:
    def __init__(self):
        self.peername: Address = None
        self.sockname: Address = None
        self.cipher_recv_tss: list[float] = []
        self.cipher_send_tss: list[float] = []
        self.plain_data: list[tuple[float, bytes]] = []

        self.cipher_suite: str = None
        self.protocol_version: str = None
        self.alpn: str = None

    @classmethod
    def from_tuple(cls, peername: tuple, sockname: tuple):
        conn = cls()
        conn.peername = Address.from_tuple(peername)
        conn.sockname = Address.from_tuple(sockname)
        return conn

    def __eq__(self, value: Connection):
        if isinstance(value, Connection):
            return self.peername == value.peername and self.sockname == value.sockname
        return False

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
        return f"Connection: {self.peername} <-> {self.sockname}, cipher_suite={self.cipher_suite}, protocol_version={self.protocol_version}, alpn={self.alpn}"

    def __repr__(self):
        return f"Connection(peername={self.peername}, sockname={self.sockname}, cipher_suite={self.cipher_suite}, protocol_version={self.protocol_version}, alpn={self.alpn})"

    def __contains__(self, item: Address | tuple | list):
        return self.peername == item or self.sockname == item

    def ciphertext_handle(self, data):
        binary = base64.b64decode(data['payload'])
        packet = TLS(binary)
        if packet.haslayer(TLSApplicationData):
            if data['direction'] == 'recv':
                self.cipher_recv_tss.append(data['ts'])
            else:
                self.cipher_send_tss.append(data['ts'])

    def plaintext_handle(self, data):
        binary = base64.b64decode(data['payload'])
        if data['direction'] == 'recv':
            self.plain_data.append((data['ts'], binary))


class Session:
    def __init__(self, report_cb=None):
        self.report_cb = report_cb
        self.interanl: Connection = None
        self.external: Connection = None
        self.external_sni: str = None
        self.ts_start: float = None
        self.ts_end: float = None

        self.in2ex_pkts: list[PacketType] = []
        self.ex2in_pkts: list[PacketType] = []

        self.sessionid: int = -1

    def __contains__(self, item: Connection | Address | tuple | list):
        if isinstance(item, Connection):
            return self.interanl == item or self.external == item
        else:
            return item in self.interanl or (self.external and item in self.external)

    def __eq__(self, value):
        if isinstance(value, Session):
            return self.interanl == value.interanl and self.external == value.external
        return False

    def find_connection(self, item: Address | tuple | list) -> Connection | None:
        """
        查找连接
        :param item: 地址或连接对象
        :return: 连接对象或 None
        """
        if item in self.interanl:
            return self.interanl
        elif item in self.external:
            return self.external
        return None

    def check_packet(self, to_conn: Connection):
        if not (self.interanl and self.external):
            return

        if to_conn == self.interanl:
            conn = self.external
            to_conn = self.interanl
            # pkts_list = self.ex2in_pkts
        elif to_conn == self.external:
            conn = self.interanl
            to_conn = self.external
            # pkts_list = self.in2ex_pkts
        else:
            raise ValueError(f"未知连接: {conn}")

        plain_left = []
        while len(conn.plain_data) > 0:
            ts_start: float = None
            ts_end: float = None
            ts_index: int = None
            plain_ts, plain_data = conn.plain_data.pop(0)

            if len(conn.cipher_recv_tss) == 0:
                raise ValueError(f"接受密文时间戳列表为空: {conn.cipher_recv_tss}")
            if plain_ts < conn.cipher_recv_tss[0]:
                raise ValueError(f"明文时间戳小于接受密文时间戳: {plain_ts} < {conn.cipher_recv_tss[0]}")
            for ts_index, ts in enumerate(conn.cipher_recv_tss):
                if ts < plain_ts:
                    ts_start = ts
                else:
                    break

            if len(to_conn.cipher_send_tss) == 0:
                plain_left.append((plain_ts, plain_data))
                continue
            if plain_ts > to_conn.cipher_send_tss[-1]:
                plain_left.append((plain_ts, plain_data))
                continue
            for ts_index, ts in enumerate(to_conn.cipher_send_tss):
                if ts > plain_ts:
                    ts_end = ts
                    break

            if ts_start and ts_end:
                pkt = PacketType(
                    source_ip=conn.peername.ip,
                    source_port=conn.peername.port,
                    destination_ip=to_conn.peername.ip,
                    destination_port=to_conn.peername.port,
                    cipher_suite=conn.cipher_suite,
                    payload=plain_data,
                    protocol_version=conn.protocol_version,
                    packet_size=len(plain_data),
                    delay=ts_end - ts_start,
                    timestamp=plain_ts,
                )
                self.report_cb(self, pkt)
            else:
                plain_left.append((plain_ts, plain_data))
        conn.plain_data = plain_left

    def set_conn_cipher(self, conn: Connection, data: dict):
        if conn == self.interanl:
            conn = self.interanl
        elif conn == self.external:
            conn = self.external
        else:
            raise ValueError(f"未知连接: {conn}")

        conn.cipher_suite = data.get("cipher_suite")
        conn.protocol_version = data.get("protocol_version")
        conn.alpn = data.get("alpn")


class Reporter:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.listen_thread = None
        self.pipe = PipeReader(ctx.PIPE_PATH)
        self.db: TrafficDatabase = None
        self.db_lock = threading.Lock()
        self.sessions: list[Session] = []

    def __listen_worker(self):
        """
        上报数据
        """
        handlers = {
            "session": self.session_handle,
            "ciphertext": self.ciphertext_handle,
            "plaintext": self.plaintext_handle,
            "request": self.request_handle,
            "response": self.response_handle,
            "cert": self.cert_handle,
            "debug": lambda data: print(f"[DEBUG] {data}"),
        }

        for data in self.pipe.read_data():
            handle_func = handlers.get(data["name"])
            if handle_func:
                handle_func(data['data'])
            else:
                raise ValueError(f"未知数据类型: {data['name']}")

    def start(self):
        """
        启动上报线程
        """
        if self.listen_thread is None:
            self.listen_thread = threading.Thread(target=self.__listen_worker)
            self.listen_thread.start()

    def update_db(self) -> bool:
        self.db_lock.acquire()
        try:
            self.db = TrafficDatabase(
                host=self.ctx.DB_HOST,
                port=self.ctx.DB_PORT,
                user=self.ctx.DB_USER,
                password=self.ctx.DB_PASSWORD,
                database=self.ctx.DB_NAME,
            )
        except Exception as e:
            print(f"[ERROR] 数据库连接失败: {e}")
            return False
        finally:
            self.db_lock.release()
        return True

    def find_session(self, item: Address | tuple) -> Session | None:
        """
        查找会话
        :param item: 地址或连接对象
        :return: 会话对象或 None
        """
        for session in self.sessions:
            if item in session:
                return session
        return None

    def find_connection(self, conn: Connection | tuple) -> Connection | None:
        """
        查找连接
        :param conn: 连接对象
        :return: 连接对象或 None
        """
        if isinstance(conn, tuple):
            conn = Connection.from_tuple(conn[0], conn[1])
        for session in self.sessions:
            if conn in session:
                # return session.find_connection(conn)
                if session.interanl == conn:
                    return session.interanl
                else:
                    return session.external
        return None

    def report_packet(self, session: Session, packet: PacketType):
        """
        上报数据包
        :param session: 会话对象
        :param packet: 数据包对象
        """
        self.db_lock.acquire()
        try:
            if session.sessionid == -1:
                session.sessionid = self.db.insert_session(
                    internal_ip=session.interanl.peername.ip,
                    external_ip=session.external.peername.ip,
                    internal_port=session.interanl.peername.port,
                    external_port=session.external.peername.port,
                )
            self.db.insert_packet_session(
                sessionid=session.sessionid,
                source_ip=packet.source_ip,
                source_port=packet.source_port,
                destination_ip=packet.destination_ip,
                destination_port=packet.destination_port,
                cipher_suite=packet.cipher_suite,
                payload=packet.payload,
                protocol_version=packet.protocol_version,
                packet_size=packet.packet_size,
                delay=packet.delay,
            )
        except Exception as e:
            print(f"[ERROR] 数据库操作失败: {e}")
        finally:
            self.db_lock.release()

    def report_cert(self, cert: str):
        """
        上报证书
        :param cert: 证书对象
        """
        self.db_lock.acquire()
        try:
            self.db.insert_certificate(certificate=cert)
        except Exception as e:
            print(f"[ERROR] 数据库操作失败: {e}")
        finally:
            self.db_lock.release()

    def session_handle(self, data):
        status = data["status"]
        if status == "start":
            session = Session(self.report_packet)
            session.interanl = Connection.from_tuple(data["internal_peer"], data["internal_sock"])
            session.ts_start = data["ts_start"]
            self.sessions.append(session)
        elif status == "connected":
            session = self.find_session(data["internal_peer"])
            session.external = Connection.from_tuple(data["external_peer"], data["external_sock"])
            session.external_sni = data["external_sni"]
        elif status == "end":
            session = self.find_session(data["internal_peer"])
            session.ts_end = data["ts_end"]
            # self.report(session)
            self.sessions.remove(session)
        else:
            raise ValueError(f"未知会话状态: {status}")

    def ciphertext_handle(self, data):
        conn = Connection.from_tuple(data["peername"], data["sockname"])
        session = self.find_session(conn)
        if session is None:
            raise ValueError(f"未找到会话: {(data["peername"], data["sockname"])}")
        conn = session.interanl if session.interanl == conn else session.external
        if conn is None:
            raise ValueError(f"未找到连接: {(data["peername"], data["sockname"])}")
        conn.ciphertext_handle(data)
        session.check_packet(conn)

    def plaintext_handle(self, data):
        conn = Connection.from_tuple(data["peername"], data["sockname"])
        session = self.find_session(conn)
        if session is None:
            raise ValueError(f"未找到会话: {(data["peername"], data["sockname"])}")
        conn = session.interanl if session.interanl == conn else session.external
        if conn is None:
            raise ValueError(f"未找到连接: {(data["peername"], data["sockname"])}")
        conn.plaintext_handle(data)

    def request_handle(self, data):
        conn = Connection.from_tuple(data["peername"], data["sockname"])
        session = self.find_session(conn)
        if session is None:
            raise ValueError(f"未找到会话: {(data["peername"], data["sockname"])}")
        session.set_conn_cipher(conn, data)

    def response_handle(self, data):
        conn = Connection.from_tuple(data["peername"], data["sockname"])
        session = self.find_session(conn)
        if session is None:
            raise ValueError(f"未找到会话: {(data["peername"], data["sockname"])}")
        session.set_conn_cipher(conn, data)

    def cert_handle(self, data):
        self.report_cert(data["cert"])
