import pymysql


class TrafficDatabase:
    def __init__(self, host:str, port:int, user:str, password:str, database='traffic_data'):
        self.connection = pymysql.connect(
            host=host,
            user=user,
            password=password,
            database=database,
            port=port,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )

    def insert_session(self, internal_ip, external_ip, internal_port, external_port, session_start_time="", session_end_time=""):
        with self.connection.cursor() as cursor:
            sql = """
                INSERT INTO session (internal_ip, external_ip, internal_port, external_port, session_start_time, session_end_time)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (internal_ip, external_ip, internal_port, external_port, session_start_time, session_end_time))
            self.connection.commit()
            return cursor.lastrowid  # 返回插入记录的ID（sessionid）
        
    def update_session(self, sessionid, session_end_time):
        with self.connection.cursor() as cursor:
            sql = """
                UPDATE session
                SET session_end_time = %s
                WHERE id = %s
            """
            cursor.execute(sql, (session_end_time, sessionid))
            self.connection.commit()

    def insert_packet_session(self, sessionid, source_ip, source_port, destination_ip, destination_port,
                               cipher_suite, payload, protocol_version, packet_size, delay):
        with self.connection.cursor() as cursor:
            sql = """
                INSERT INTO packetsession (
                    sessionid, source_ip, source_port, destination_ip, destination_port,
                    cipher_suite, payload, protocol_version, packet_size, delay
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                sessionid, source_ip, source_port, destination_ip, destination_port,
                cipher_suite, payload, protocol_version, packet_size, delay
            ))
            self.connection.commit()

    def insert_certificate(self, certificate:str):
        with self.connection.cursor() as cursor:
            sql = """
                INSERT INTO certificate (certificate)
                VALUES (%s)
            """
            cursor.execute(sql, (certificate,))
            self.connection.commit()

    def close(self):
        self.connection.close()



class TrafficDatabaseDebug:
    def __init__(self, host:str, port:int, user:str, password:str, database='traffic_data'):
        print(f"连接到数据库: {host}:{port}, 用户: {user}, 数据库: {database}")
        self.session_cnt = 0

    def insert_session(self, internal_ip, external_ip, internal_port, external_port, session_start_time="", session_end_time=""):
        sql = """
            INSERT INTO session (internal_ip, external_ip, internal_port, external_port, session_start_time, session_end_time)
              VALUES (%s, %s, %s, %s, %s, %s)
        """
        # print(f"执行 SQL: {sql % (internal_ip, external_ip, internal_port, external_port, session_start_time, session_end_time)}".replace('\n', ' '))
        self.session_cnt += 1
        return self.session_cnt  # 返回插入记录的ID（sessionid）
        
    def insert_certificate(self,certificate:str):
        sql = """
                INSERT INTO certificate (certificate)
                VALUES (%s)
            """
        # Truncate certificate if too long for display (optional)
        display_cert = certificate[:100] + '...' if len(certificate) > 100 else certificate
        # print(f"执行 SQL: {sql % (display_cert,)}".replace('\n', ' '))
        return 0
    
    def insert_packet_session(self, sessionid, source_ip, source_port, destination_ip, destination_port,
                                 cipher_suite, payload, protocol_version, packet_size, delay):
        sql = """
            INSERT INTO packetsession (
                sessionid, source_ip, source_port, destination_ip, destination_port,
                cipher_suite, payload, protocol_version, packet_size, delay
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        payload = payload[:20] + b'...' if len(payload) > 20 else payload
        # print(f"执行 SQL: {sql % (sessionid, source_ip, source_port, destination_ip, destination_port, cipher_suite, payload, protocol_version, packet_size, delay)}".replace('\n', ' '))
        return 0
    
    def update_session(self, sessionid, session_end_time):
        sql = """
            UPDATE session
            SET session_end_time = %s
            WHERE id = %s
        """
        print(f"执行 SQL: {sql % (session_end_time, sessionid)}".replace('\n', ' '))
        return 0