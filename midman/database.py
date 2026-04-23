import pymysql


class TrafficDatabase:
    def __init__(self, host:str, port:int, user:str, password:str, database='traffic_data'):
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._database = database
        self.connection = self._create_connection()
        self._pending_packets = []
        self._batch_size = 100

    def _create_connection(self):
        conn = pymysql.connect(
            host=self._host,
            user=self._user,
            password=self._password if self._password else '',
            database=self._database,
            port=self._port,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False
        )
        return conn

    def _is_connection_alive(self):
        """检查连接是否真的可用"""
        if self.connection is None or not self.connection.open:
            return False
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            return True
        except Exception:
            return False

    def _ensure_connection(self):
        """确保连接可用，失败时重连"""
        if not self._is_connection_alive():
            self.connection = self._create_connection()

    def insert_session(self, internal_ip, external_ip, internal_port, external_port, external_sni, session_start_time="", session_end_time=""):
        self._ensure_connection()
        try:
            with self.connection.cursor() as cursor:
                sql = """
                    INSERT INTO session (internal_ip, external_ip, internal_port, external_port, external_sni, session_start_time, session_end_time)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (internal_ip, external_ip, internal_port, external_port, external_sni, session_start_time, session_end_time))
                self.connection.commit()
                return cursor.lastrowid
        except pymysql.OperationalError as e:
            self.connection = self._create_connection()
            with self.connection.cursor() as cursor:
                cursor.execute(sql, (internal_ip, external_ip, internal_port, external_port, external_sni, session_start_time, session_end_time))
                self.connection.commit()
                return cursor.lastrowid

    def update_session(self, sessionid, session_end_time):
        self._ensure_connection()
        try:
            with self.connection.cursor() as cursor:
                sql = """
                    UPDATE session
                    SET session_end_time = %s
                    WHERE id = %s
                """
                cursor.execute(sql, (session_end_time, sessionid))
                self.connection.commit()
        except (pymysql.OperationalError, pymysql.InterfaceError) as e:
            self.connection = self._create_connection()
            with self.connection.cursor() as cursor:
                cursor.execute(sql, (session_end_time, sessionid))
                self.connection.commit()

    def insert_packet_session(self, sessionid, source_ip, source_port, destination_ip, destination_port,
                               cipher_suite, payload, protocol_version, packet_size, delay, alpn, cipher_data):
        # TODO: 调试完成后移除默认值，让 None 值直接写入数据库以暴露问题
        self._pending_packets.append((
            sessionid,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            # cipher_suite or 'TLS_AES_256_GCM_SHA384',
            cipher_suite,
            payload,
            # protocol_version or 'TLSv1.3',
            protocol_version,
            packet_size,
            delay,
            alpn,
            # cipher_data or b'',
            cipher_data,
        ))
        if len(self._pending_packets) >= self._batch_size:
            self.flush()

    def flush(self):
        """刷新待写入的数据，失败时保留数据用于重试"""
        if not self._pending_packets:
            return
        self._ensure_connection()
        try:
            self._do_flush()
        except pymysql.OperationalError:
            self.connection = self._create_connection()
            self._do_flush()
        except (AttributeError, TypeError) as e:
            # pymysql 内部出错（如 None 参数），记录并丢弃这批数据，避免 worker 崩溃
            print(f"[WARN] 数据写入失败，已丢弃: {e}")
            self._pending_packets = []

    def _do_flush(self):
        """执行实际的批量写入操作，失败时保留数据"""
        packets = self._pending_packets
        try:
            with self.connection.cursor() as cursor:
                sql = """
                    INSERT INTO packetsession (
                        sessionid, source_ip, source_port, destination_ip, destination_port,
                        cipher_suite, payload, protocol_version, packet_size, delay, alpn, cipher_data
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.executemany(sql, packets)
                self.connection.commit()
            self._pending_packets = []  # 成功后清空
        except Exception:
            # 失败时恢复数据，不丢失
            self._pending_packets = packets
            raise

    def commit(self):
        self.flush()

    def insert_certificate(self, certificate: str):
        self._ensure_connection()
        try:
            with self.connection.cursor() as cursor:
                sql = """
                    INSERT INTO certificate (certificate)
                    VALUES (%s)
                """
                cursor.execute(sql, (certificate,))
                self.connection.commit()
        except (pymysql.OperationalError, pymysql.InterfaceError) as e:
            if "Packet sequence number wrong" in str(e) or "Lost connection" in str(e) or "gone away" in str(e).lower():
                # 连接已失效，强制重建
                self.connection = self._create_connection()
                with self.connection.cursor() as cursor:
                    cursor.execute(sql, (certificate,))
                    self.connection.commit()
            else:
                raise

    def close(self):
        self.flush()
        self.connection.close()