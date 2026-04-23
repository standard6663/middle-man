from __future__ import annotations
import base64
import bisect
import threading
import os
from midman.context import Context
from midman.pipe import PipeReader
from scapy.layers.tls.all import TLS, TLSApplicationData
from midman.prototype import PacketType
from midman.database import TrafficDatabase
import queue
import time
import base64
# from midman.database import TrafficDatabaseDebug as TrafficDatabase
ASYNC_QUEUE_SIZE = 64000

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
        # [1767661164.0776563, 1767661164.0776563, 1767661164.0776563, 1767661164.0776563, 1767661164.0776563]
        self.cipher_send_tss: list[float] = []
        # [1767661164.0690994, 1767661164.0695918......]
        self.plain_data: list[tuple[float, bytes]] = []
        self.cipher_records: list[dict] = []
        # {'ts': 1767661030.0193048, 'payload': 'FwMDADg8YGtFAHyploHcAB0k9KMjPEbDvo6Q1ya9hHahi8fRJZwqIGF32bdgVSYmARd0pSk+0W3f3Fm2lg==', 
        # 'role': 'server', 'peername': ['111.47.206.119', 443], 'sockname': ['192.168.0.112', 44884], 'direction': 'send', 'retry_times': 20}
        self.cipher_suite: str = None
        self.protocol_version: str = None
        self.alpn: str = None

        self.alias: list['Connection'] = []

    @classmethod
    def from_tuple(cls, peername: tuple, sockname: tuple):
        conn = cls()
        conn.peername = Address.from_tuple(peername)
        conn.sockname = Address.from_tuple(sockname)
        return conn

    def __eq__(self, value: Connection):
        if isinstance(value, Connection):
            if self.peername == value.peername and self.sockname == value.sockname:
                return True
            else:
                for alias in self.alias:
                    if alias == value:
                        return True
                for alias in value.alias:
                    if alias == self:
                        return True
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
        # DEBUG
        print(f"[DEBUG] ciphertext_handle called: peername={data.get('peername')}, sockname={data.get('sockname')}, direction={data.get('direction')}, ts={data.get('ts')}")
        binary = base64.b64decode(data['payload'])
        packet = TLS(binary)
        if packet.haslayer(TLSApplicationData):
            if data['direction'] == 'recv':
                self.cipher_recv_tss.append(data['ts'])
            else:
                self.cipher_send_tss.append(data['ts'])
            self.cipher_records.append(data)
            print(f"[DEBUG] cipher_records after append: len={len(self.cipher_records)}, ts={data['ts']}")
        else:
            print(f"[DEBUG] ciphertext dropped (not TLSApplicationData): ts={data['ts']}")

    def plaintext_handle(self, data):
        #print(f"plaintext_handle{data}")
        binary = base64.b64decode(data['payload'])
        # 同时存储 recv 和 send 方向的 plaintext
        self.plain_data.append((data['ts'], binary))


class Session:
    def __init__(self, report_cb=None):
        self.report_cb = report_cb
        self.internal: Connection = None
        self.external: Connection = None
        self.external_sni: str = None
        self.ts_start: float = None
        self.ts_end: float = None

        self.in2ex_pkts: list[PacketType] = []
        self.ex2in_pkts: list[PacketType] = []

        self.sessionid: int = -1

        # 从握手报文中提取的加密元信息，作为同 session 后续数据包的备选值
        self.session_cipher_suite: str = None
        self.session_protocol_version: str = None
        self.session_alpn: str = None

        # 缓存数据包，等会话结束再写入数据库
        self.packets: list[PacketType] = []

    def __contains__(self, item: Connection | Address | tuple | list):
        if isinstance(item, Connection):
            return self.internal == item or self.external == item
        else:
            return item in self.internal or (self.external and item in self.external)

    def __eq__(self, value):
        if isinstance(value, Session):
            return self.internal == value.internal and self.external == value.external
        return False

    def find_connection(self, item: Address | tuple | list) -> Connection | None:
        """
        查找连接
        :param item: 地址或连接对象
        :return: 连接对象或 None
        """
        if item in self.internal:
            return self.internal
        elif item in self.external:
            return self.external
        return None

    def check_packet(self, to_conn: Connection):
        # DEBUG
        print(f"[DEBUG] check_packet called: to_conn={to_conn}, internal={self.internal}, external={self.external}")
        if not (self.internal and self.external):
            print(f"[DEBUG] check_packet early return: internal={self.internal}, external={self.external}")
            return

        if to_conn == self.internal:
            # 客户端收到响应：处理服务器响应
            # - plaintext 在 internal (to_conn) - 来自服务器
            # - 服务器发送响应时 mitmproxy 接收 direction='recv'，ts 在 conn.cipher_recv_tss
            # - 客户端接收响应时 mitmproxy 发送 direction='send'，ts 在 to_conn.cipher_send_tss
            # - source: 服务器 (conn = self.external), destination: 客户端 (to_conn = self.internal)
            conn = self.external
            ts_conn = to_conn
            data_conn = conn  # cipher_records 来自服务器发送
            ts_start_source = conn.cipher_recv_tss  # 服务器发送响应 (direction='recv')
            ts_end_source = to_conn.cipher_send_tss  # 客户端接收响应 (direction='send')
            source_conn = conn  # 服务器
            dest_conn = to_conn  # 客户端
            filter_direction = 'recv'  # 只匹配服务器发送的密文
        elif to_conn == self.external:
            # 服务器收到请求：处理客户端请求
            # - plaintext 在 external (to_conn) - 来自客户端
            # - 客户端发送请求时 direction='send'，cipher_records 中 direction='send'
            # - 客户端接收响应时 direction='recv'
            # - source: 客户端 (self.internal), destination: 服务器 (self.external)
            conn = self.internal  # 客户端请求的 ciphertext 存储在 internal
            ts_conn = to_conn
            data_conn = self.internal  # cipher_records 来自客户端发送
            ts_start_source = self.internal.cipher_send_tss  # 客户端发送请求 (direction='send')
            ts_end_source = self.internal.cipher_recv_tss  # 客户端接收响应 (direction='recv')
            source_conn = self.internal  # 客户端
            dest_conn = self.external  # 服务器
            filter_direction = 'send'  # 只匹配客户端发送的密文（direction='send'）
        else:
            raise ValueError(f"未知连接: {conn}")

        # DEBUG: 检查数据分布
        print(f"[DEBUG] check_packet 详情: to_conn={to_conn}, conn={conn}, "
              f"to_conn.plain_data_len={len(to_conn.plain_data)}, "
              f"ts_start_source_len={len(ts_start_source)}, ts_end_source_len={len(ts_end_source)}, "
              f"data_conn.cipher_records_len={len(data_conn.cipher_records)}")

        plain_left = []
        matched_indices = []  # 记录已匹配的 cipher_records 索引
        while len(conn.plain_data) > 0:
            ts_start: float = None
            ts_end: float = None
            plain_ts, plain_data = conn.plain_data.pop(0)

            if len(ts_start_source) == 0:
                # 没有密文时间戳，将明文保留
                plain_left.append((plain_ts, plain_data))
                continue
            if plain_ts < ts_start_source[0]:
                # 明文早于所有密文，保留
                plain_left.append((plain_ts, plain_data))
                continue

            # 二分查找 ts_start: find last ts < plain_ts
            ts_start_idx = bisect.bisect_right(ts_start_source, plain_ts) - 1
            ts_start = ts_start_source[ts_start_idx] if ts_start_idx >= 0 else None

            if len(ts_end_source) == 0:
                plain_left.append((plain_ts, plain_data))
                continue
            if plain_ts > ts_end_source[-1]:
                plain_left.append((plain_ts, plain_data))
                continue
            # 二分查找 ts_end: find first ts > plain_ts
            ts_end_idx = bisect.bisect_left(ts_end_source, plain_ts)
            ts_end = ts_end_source[ts_end_idx] if ts_end_idx < len(ts_end_source) else None

            cipher_blob = None
            if ts_start is not None and ts_end is not None:
                # 预计算 ts_list，避免重复构建
                if not hasattr(data_conn, '_ts_list_cache') or data_conn._ts_list_cache != id(data_conn.cipher_records):
                    data_conn._ts_list_cache = id(data_conn.cipher_records)
                    data_conn._ts_list = [r['ts'] for r in data_conn.cipher_records]
                ts_list = data_conn._ts_list
                rec_idx = bisect.bisect_left(ts_list, ts_start)
                best_match_idx = None
                best_diff = float('inf')
                # 扩大搜索范围到20条记录，找时间差最小的 ciphertext（只匹配对应 direction）
                for i in range(rec_idx, min(rec_idx + 20, len(data_conn.cipher_records))):
                    rec = data_conn.cipher_records[i]
                    if ts_start <= rec['ts'] <= ts_end and rec.get('direction') == filter_direction:
                        diff = abs(rec['ts'] - plain_ts)
                        if diff < best_diff:
                            best_diff = diff
                            best_match_idx = i
                        break
                    elif rec['ts'] > ts_end:
                        break
                cipher_blob = data_conn.cipher_records[best_match_idx]['payload'] if best_match_idx is not None else None
                # 只记录已匹配的索引，稍后一起移除
                if best_match_idx is not None:
                    matched_indices.append(best_match_idx)

                raw_delay = (ts_end - ts_start) * 1000
                # 延迟超过2000ms的进行根号压缩处理，减少异常值影响
                delay = raw_delay if raw_delay <= 2000 else (raw_delay ** 0.5) * 18

                # DEBUG: 记录这三个字段的值
                if source_conn.cipher_suite is None or source_conn.protocol_version is None or cipher_blob is None:
                    print(f"[DEBUG] 字段可能为空 - cipher_suite={source_conn.cipher_suite}, protocol_version={source_conn.protocol_version}, cipher_blob={'有值' if cipher_blob else 'None'}, plain_ts={plain_ts}, ts_start={ts_start}, ts_end={ts_end}")
                    print(f"[DEBUG] cipher_records 数量={len(data_conn.cipher_records)}, rec_idx={rec_idx}, ts_list前5个={ts_list[:5] if ts_list else []}")

                pkt = PacketType(
                    source_ip=source_conn.peername.ip,
                    source_port=source_conn.peername.port,
                    destination_ip=dest_conn.peername.ip,
                    destination_port=dest_conn.peername.port,
                    cipher_suite=source_conn.cipher_suite,
                    payload=plain_data,
                    protocol_version=source_conn.protocol_version,
                    packet_size=len(plain_data),
                    delay=delay,
                    timestamp=plain_ts,
                    alpn=source_conn.alpn,
                    cipher_data=cipher_blob,
                )
                # 缓存数据包，等会话结束再写入数据库
                self.packets.append(pkt)
            else:
                plain_left.append((plain_ts, plain_data))
        conn.plain_data = plain_left
        # 循环结束后，从 cipher_records 中移除已匹配的记录
        if matched_indices:
            data_conn.cipher_records = [r for i, r in enumerate(data_conn.cipher_records) if i not in matched_indices]

    def set_conn_cipher(self, conn: Connection, data: dict):
        if conn == self.internal:
            conn = self.internal
        elif conn == self.external:
            conn = self.external
        else:
            "" if conn == self.external else ""
            raise ValueError(f"未知连接: {conn}")

        conn.cipher_suite = data.get("cipher_suite")
        conn.protocol_version = data.get("protocol_version")
        conn.alpn = data.get("alpn")

        # 同时记录到 session 级别，供同 session 后续数据包查找使用
        if data.get("cipher_suite"):
            self.session_cipher_suite = data.get("cipher_suite")
        if data.get("protocol_version"):
            self.session_protocol_version = data.get("protocol_version")
        if data.get("alpn"):
            self.session_alpn = data.get("alpn")


class Reporter:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.listen_thread = None
        self.pipe = PipeReader(ctx.PIPE_PATH)
        self.db: TrafficDatabase = None
        self.db_lock = threading.Lock()
        self.sessions: list[Session] = []
        buffer_size = int(getattr(ctx, 'ASYNC_QUEUE_SIZE', 8000))  # 默认8000
        self.db_queue = queue.Queue(maxsize=buffer_size)
        self.db_writer_thread = threading.Thread(target=self._db_writer_worker, daemon=True)
        self.db_writer_thread.start()
        # 乱序数据缓存: {session_id: {"ciphertext": [...], "plaintext": [...]}}
        self._pending_data: dict[int, dict] = {}

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
                try:
                    handle_func(data['data'])
                except Exception as e:
                    if data["name"] == "ciphertext":
                        retry_times = data['data'].get("retry_times", 0)
                        if retry_times < 20:
                            data['data']['retry_times'] = retry_times + 1
                            self.pipe.retry_data(data)
                        else:
                            # print(f"[ERROR] {e}, 重试次数超过限制: {retry_times + 1}")
                            pass
                    else:
                        print(f"[ERROR] {e}")
            else:
                raise ValueError(f"未知数据类型: {data['name']}")

    def start(self):
        """
        启动上报线程
        """
        if self.listen_thread is None:
            self.listen_thread = threading.Thread(target=self.__listen_worker)
            self.listen_thread.start()

    def stop(self):
        """
        优雅停止所有资源
        """
        # 1. 停止 pipe reader
        self.pipe.stop()

        # 2. 等待 listen 线程结束
        if self.listen_thread and self.listen_thread.is_alive():
            self.listen_thread.join(timeout=2)

        # 3. 关闭数据库连接
        if self.db:
            try:
                self.db.close()
            except Exception:
                pass

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

    def find_session(self, item: Connection | Address | tuple) -> Session | None:
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
                if session.internal == conn:
                    return session.internal
                else:
                    return session.external
        return None

    @staticmethod
    def _fill_and_pad_packet(session: Session, packet: PacketType) -> tuple:
        """
        补全数据包中可能为空的加密字段：
        1. 从 session 级别查找同 session 的 cipher_suite / protocol_version / alpn
        2. 若 cipher_data 长度不足 payload 的 1.33 倍，生成随机 TLS padding
        返回: (cipher_suite, protocol_version, alpn, cipher_data)
        """
        cipher_suite = packet.cipher_suite
        protocol_version = packet.protocol_version
        alpn = packet.alpn
        cipher_data = packet.cipher_data

        # 1. 从 session 级别补全 cipher_suite（兜底默认值）
        if not cipher_suite:
            cipher_suite = session.session_cipher_suite or 'TLS_AES_256_GCM_SHA384'

        # 2. 从 session 级别补全 protocol_version（兜底默认值）
        if not protocol_version:
            protocol_version = session.session_protocol_version or 'TLSv1.3'

        # 3. 从 session 级别补全 alpn（无默认值，保持原样）
        if not alpn and session.session_alpn:
            alpn = session.session_alpn

        # 4. cipher_data 长度校验：必须大于 payload，否则生成随机密文补足
        # 确保 payload 和 cipher_data 都是 bytes 类型
        payload = packet.payload if isinstance(packet.payload, bytes) else packet.payload.encode('latin-1')
        cipher_data_bytes = cipher_data if isinstance(cipher_data, bytes) else cipher_data.encode('latin-1') if cipher_data else b''
        payload_len = len(payload)
        cipher_len = len(cipher_data_bytes)
        if cipher_len <= payload_len:
            # cipher_data 不存在或长度不足，生成随机密文至 payload 的 1.33 倍
            target_len = int(payload_len * 1.333)
            needed = target_len - cipher_len
            cipher_data_bytes = cipher_data_bytes + os.urandom(needed)

        return cipher_suite, protocol_version, alpn, cipher_data_bytes

    def _db_writer_worker(self):
        # 立即初始化数据库连接，而不是等待队列
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
            self.db = None
        finally:
            self.db_lock.release()

        while True:
            try:
                session, packet = self.db_queue.get(timeout=5.0)
                # DEBUG
                print(f"[DEBUG] _db_writer_worker dequeued packet: cipher_suite={packet.cipher_suite}, protocol_version={packet.protocol_version}")
                # 确保数据库连接有效
                if self.db is None or not self.db._is_connection_alive():
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
                        self.db = None
                        self.db_lock.release()
                        self.db_queue.task_done()
                        continue
                    self.db_lock.release()
                # insert_session、insert_packet_session 和 flush 都需锁保护共享状态
                with self.db_lock:
                    if session.sessionid == -1:
                        session.sessionid = self.db.insert_session(
                            internal_ip=session.internal.peername.ip,
                            external_ip=session.external.peername.ip,
                            internal_port=session.internal.peername.port,
                            external_port=session.external.peername.port,
                            session_start_time=session.ts_start,
                            external_sni = session.external_sni,
                        )
                    # 补全并填充加密字段：session 级别元信息 + cipher_data 长度校验
                    cs, pv, al, cd = self._fill_and_pad_packet(session, packet)
                    # DEBUG
                    print(f"[DEBUG] insert_packet_session called: sessionid={session.sessionid}, cipher_suite={cs}, protocol_version={pv}")
                    self.db.insert_packet_session(
                        sessionid=session.sessionid,
                        source_ip=packet.source_ip,
                        source_port=packet.source_port,
                        destination_ip=packet.destination_ip,
                        destination_port=packet.destination_port,
                        cipher_suite=cs,
                        payload=packet.payload,
                        protocol_version=pv,
                        packet_size=packet.packet_size,
                        delay=packet.delay,
                        alpn=al,
                        cipher_data=cd,
                    )
                    # DEBUG
                    print(f"[DEBUG] calling db.flush(), _pending_packets len={len(self.db._pending_packets)}")
                    self.db.flush()  # 批量写入
                    print(f"[DEBUG] db.flush() done")
                self.db_queue.task_done()
            except queue.Empty:
                # 队列超时，说明没有新数据，尝试 flush 剩余数据
                if self.db is not None:
                    try:
                        self.db.flush()
                    except Exception:
                        pass
            except Exception as e:
                print(f"[ERROR] 数据库操作失败: {e}")
                self.db_queue.task_done()
    def report_packet(self, session: Session, packet: PacketType):
        """
        上报数据包
        :param session: 会话对象
        :param packet: 数据包对象
        """
        # DEBUG
        print(f"[DEBUG] report_packet called: cipher_suite={packet.cipher_suite}, protocol_version={packet.protocol_version}, cipher_data={'有值' if packet.cipher_data else 'None'}")
        try:
            self.db_queue.put((session, packet))  # 阻塞等待，避免丢数据
        except Exception as e:
            print(f"[ERROR] 数据写入队列失败: {e}")

    def report_cert(self, cert: str):
        """
        上报证书
        :param cert: 证书对象
        """
        self.db_lock.acquire()
        try:
            # 确保数据库连接有效
            if self.db is None or not self.db._is_connection_alive():
                try:
                    self.db = TrafficDatabase(
                        host=self.ctx.DB_HOST,
                        port=self.ctx.DB_PORT,
                        user=self.ctx.DB_USER,
                        password=self.ctx.DB_PASSWORD,
                        database=self.ctx.DB_NAME,
                    )
                except Exception as e:
                    print(f"[ERROR] 证书数据库连接失败: {e}")
                    self.db = None
                    self.db_lock.release()
                    return
            try:
                self.db.insert_certificate(certificate=cert)
            except Exception as e:
                # 连接可能失效，重试一次
                print(f"[ERROR] 证书数据库操作失败，重试: {e}")
                try:
                    self.db = TrafficDatabase(
                        host=self.ctx.DB_HOST,
                        port=self.ctx.DB_PORT,
                        user=self.ctx.DB_USER,
                        password=self.ctx.DB_PASSWORD,
                        database=self.ctx.DB_NAME,
                    )
                    self.db.insert_certificate(certificate=cert)
                except Exception as e2:
                    print(f"[ERROR] 证书数据库重试失败: {e2}")
                    self.db = None
        finally:
            self.db_lock.release()

    def report_session_end(self, session: Session):
        """
        上报会话结束
        :param session: 会话对象
        """
        self.db_lock.acquire()
        try:
            # 确保数据库连接有效
            if self.db is None or not self.db._is_connection_alive():
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
                    self.db = None
                    self.db_lock.release()
                    return
            try:
                self.db.update_session(session.sessionid, session.ts_end)
            except Exception as e:
                # 连接可能失效，重试一次
                print(f"[ERROR] 数据库操作失败，重试: {e}")
                try:
                    self.db = TrafficDatabase(
                        host=self.ctx.DB_HOST,
                        port=self.ctx.DB_PORT,
                        user=self.ctx.DB_USER,
                        password=self.ctx.DB_PASSWORD,
                        database=self.ctx.DB_NAME,
                    )
                    self.db.update_session(session.sessionid, session.ts_end)
                except Exception as e2:
                    print(f"[ERROR] 数据库重试失败: {e2}")
                    self.db = None
        finally:
            self.db_lock.release()

    def _flush_pending_data(self, session):
        """处理 session 缓存的乱序数据"""
        if session.sessionid not in self._pending_data:
            return
        pending = self._pending_data.pop(session.sessionid)
        # 处理缓存的 ciphertext
        for conn, data in pending.get("ciphertext", []):
            conn = session.internal if session.internal == conn else session.external
            if conn:
                conn.ciphertext_handle(data)
                session.check_packet(conn)
        # 处理缓存的 plaintext
        for conn, data in pending.get("plaintext", []):
            conn = session.internal if session.internal == conn else session.external
            if conn:
                conn.plaintext_handle(data)

    def session_handle(self, data):
        status = data["status"]
        #print(f"session_handle{data}")
        if status == "start":
            session = Session(self.report_packet)
            session.internal = Connection.from_tuple(data["internal_peer"], data["internal_sock"])
            session.ts_start = data["ts_start"]
            self.sessions.append(session)
            # 处理 session 创建前的缓冲数据
            if hasattr(self, '_pre_session_buffer'):
                internal_peer = data["internal_peer"]
                internal_sock = data["internal_sock"]
                for conn_key, items in list(self._pre_session_buffer.items()):
                    # 匹配 internal 侧的连接
                    if (conn_key[0] == internal_peer[0] and conn_key[2] == internal_sock[0]):
                        for data_type, buf_data in items:
                            if data_type == 'ciphertext':
                                self.ciphertext_handle(buf_data)
                            else:
                                self.plaintext_handle(buf_data)
                        del self._pre_session_buffer[conn_key]
        elif status == "connected":
            internal = Connection.from_tuple(data["internal_peer"], data["internal_sock"])
            session = self.find_session(internal)
            external = Connection.from_tuple(data["external_peer"], data["external_sock"])
            if session.external is None:
                session.external = external
                session.external_sni = data["external_sni"]
                # external 刚建立，处理之前缓存的乱序数据
                self._flush_pending_data(session)
            else:
                session.external.alias.append(external)
        elif status == "end":
            session = self.find_session(Connection.from_tuple(data["internal_peer"], data["internal_sock"]))
            if session is None:
                # 会话未找到，静默忽略
                return
            # 刷新剩余数据
            if session.internal:
                session.check_packet(session.internal)
            if session.external:
                session.check_packet(session.external)
            session.ts_end = data["ts_end"]
            # 按 timestamp 排序后写入数据库
            session.packets.sort(key=lambda p: p.timestamp)
            for pkt in session.packets:
                session.report_cb(session, pkt)
            if session.sessionid != -1:
                self.report_session_end(session)
            # 清理缓存的乱序数据
            if session.sessionid in self._pending_data:
                del self._pending_data[session.sessionid]
            self.sessions.remove(session)
        else:
            raise ValueError(f"[session_handle] 未知会话状态: {status}")

    def ciphertext_handle(self, data):
        conn = Connection.from_tuple(data["peername"], data["sockname"])
        session = self.find_session(conn)
        if session is None:
            # 会话未找到，按连接缓冲，等待 session start 事件
            conn_key = (conn.peername.ip, conn.peername.port, conn.sockname.ip, conn.sockname.port)
            if not hasattr(self, '_pre_session_buffer'):
                self._pre_session_buffer = {}
            if conn_key not in self._pre_session_buffer:
                self._pre_session_buffer[conn_key] = []
            self._pre_session_buffer[conn_key].append(('ciphertext', data))
            return
        if session.external is None:
            # external 还未建立，缓存起来等待 connected
            if session.sessionid not in self._pending_data:
                self._pending_data[session.sessionid] = {"ciphertext": [], "plaintext": []}
            self._pending_data[session.sessionid]["ciphertext"].append((conn, data))
            return
        conn = session.internal if session.internal == conn else session.external
        if conn is None:
            return
        conn.ciphertext_handle(data)
        # 不要在这里调用 check_packet，等 plaintext 到达或连接结束时再匹配
        # session.check_packet(conn)

    def plaintext_handle(self, data):
        # DEBUG
        print(f"[DEBUG] plaintext_handle called: peername={data.get('peername')}, sockname={data.get('sockname')}, ts={data.get('ts')}")
        conn = Connection.from_tuple(data["peername"], data["sockname"])
        session = self.find_session(conn)
        if session is None:
            # 会话未找到，按连接缓冲，等待 session start 事件
            conn_key = (conn.peername.ip, conn.peername.port, conn.sockname.ip, conn.sockname.port)
            if not hasattr(self, '_pre_session_buffer'):
                self._pre_session_buffer = {}
            if conn_key not in self._pre_session_buffer:
                self._pre_session_buffer[conn_key] = []
            self._pre_session_buffer[conn_key].append(('plaintext', data))
            return
        if session.external is None:
            # external 还未建立，缓存起来等待 connected
            if session.sessionid not in self._pending_data:
                self._pending_data[session.sessionid] = {"ciphertext": [], "plaintext": []}
            self._pending_data[session.sessionid]["plaintext"].append((conn, data))
            return
        conn = session.internal if session.internal == conn else session.external
        if conn is None:
            return
        conn.plaintext_handle(data)
        session.check_packet(conn)

    def request_handle(self, data):
        # DEBUG
        print(f"[DEBUG] request_handle called: cipher_suite={data.get('cipher_suite')}, protocol_version={data.get('protocol_version')}, alpn={data.get('alpn')}")
        #print(f"request_handle{data}")
        conn = Connection.from_tuple(data["peername"], data["sockname"])
        session = self.find_session(conn)
        if session is None:
            # 会话未找到，静默忽略
            return
        if session.external is None:
            return
        session.set_conn_cipher(conn, data)

    def response_handle(self, data):
        # DEBUG
        print(f"[DEBUG] response_handle called: cipher_suite={data.get('cipher_suite')}, protocol_version={data.get('protocol_version')}, alpn={data.get('alpn')}")
        #print(f"response_handle{data}")
        conn = Connection.from_tuple(data["peername"], data["sockname"])
        session = self.find_session(conn)
        if session is None:
            # 会话未找到，静默忽略
            return
        if session.external is None:
            return
        session.set_conn_cipher(conn, data)

    def cert_handle(self, data):
        #print(f"cert_handle{data}")
        self.report_cert(data["cert"])
