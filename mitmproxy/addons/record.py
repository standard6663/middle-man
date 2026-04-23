from mitmproxy import ctx
from midman.pipe import PipeWriter
from mitmproxy import http
import base64
import time


class Record:
    def __init__(self) -> None:
        # 每次创建新的 PipeWriter（Record 是单例，不会重复创建）
        # 避免通过 ctx.options.pipe_writer 共享导致的问题
        self.pipe = PipeWriter(ctx.options.pipe_path)
        self._flow_start_time = {}
        # 缓存 server_conn 信息用于 session
        self._server_info = {}
        # 缓存服务器实际选择的密码套件: {(server_ip, server_port): cipher_name}
        self._server_cipher = {}

    def _get_flow_key(self, flow):
        """获取 flow 的唯一标识"""
        return (flow.client_conn.peername, flow.client_conn.sockname)

    def request(self, flow: http.HTTPFlow):
        conn = flow.client_conn
        data = {
            'peername': conn.peername,
            'sockname': conn.sockname,
            'cipher_suite': conn.cipher,
            'protocol_version': conn.tls_version,
            'alpn': conn.alpn.decode() if conn.alpn else ""
        }
        self.pipe.write("request", data)

        # 发送 session start（如果还没有）
        key = self._get_flow_key(flow)
        if key not in self._server_info:
            self.pipe.write("session", {
                "status": "start",
                "internal_peer": conn.peername,
                "internal_sock": conn.sockname,
                "ts_start": conn.timestamp_start,
            })

    def response(self, flow: http.HTTPFlow):
        conn = flow.server_conn
        server_key = (conn.peername[0], conn.peername[1])
        # 优先使用 tls_established_server 时记录的实际套件，否则降级到 conn.cipher
        cipher_suite = self._server_cipher.get(server_key, conn.cipher)
        data = {
            'peername': conn.peername,
            'sockname': conn.sockname,
            'cipher_suite': cipher_suite,
            'protocol_version': conn.tls_version,
            'alpn': conn.alpn.decode() if conn.alpn else ""
        }
        self.pipe.write("response", data)

    def client_connected(self, client):
        pass

    def client_disconnected(self, client):
        data = {
            "status": "end",
            "internal_peer": client.peername,
            "internal_sock": client.sockname,
            "ts_end": client.timestamp_end,
        }
        self.pipe.write("session", data)

    def server_connected(self, data):
        server = data.server
        client = data.client
        if not client:
            return
        key = (client.peername, client.sockname)
        self._server_info[key] = {
            "external_peer": server.peername,
            "external_sock": server.sockname,
            "external_sni": server.sni,
        }
        # 发送 session connected
        self.pipe.write("session", {
            "status": "connected",
            "internal_peer": client.peername,
            "internal_sock": client.sockname,
            "external_peer": server.peername,
            "external_sock": server.sockname,
            "external_sni": server.sni,
        })

    def tls_established_server(self, tls_start):
        """TLS 握手完成后，读取服务器实际选择的密码套件"""
        ssl_cipher = tls_start.ssl_conn.get_cipher_name()
        if ssl_cipher:
            server = tls_start.conn
            key = (server.peername[0], server.peername[1])
            self._server_cipher[key] = ssl_cipher
            print(f"[Record] 服务器实际选择: {ssl_cipher} @ {server.peername}")

    def tcp_start(self, flow):
        """TCP 连接开始"""
        self._flow_start_time[self._get_flow_key(flow)] = time.time()
        # 发送 session start
        key = self._get_flow_key(flow)
        server_info = self._server_info.get(key, {})
        self.pipe.write("session", {
            "status": "start",
            "internal_peer": flow.client_conn.peername,
            "internal_sock": flow.client_conn.sockname,
            "ts_start": flow.client_conn.timestamp_start,
            "external_peer": server_info.get("external_peer"),
            "external_sock": server_info.get("external_sock"),
            "external_sni": server_info.get("external_sni"),
        })

    def tcp_message(self, flow):
        """TCP 消息，捕获解密后的数据用于 timestamp 匹配"""
        for msg in flow.messages:
            # msg.from_client == True: 客户端 -> 服务器 (mitmproxy 发送)
            # msg.from_client == False: 服务器 -> 客户端 (mitmproxy 接收)
            direction = 'send' if msg.from_client else 'recv'
            ts = time.time()
            payload_b64 = base64.b64encode(msg.content).decode('utf-8')

            # 同时发送 ciphertext 和 plaintext（mitmproxy 已经解密，原始 TLS 记录拿不到）
            # ciphertext 用于存储时间戳（cipher_recv_tss / cipher_send_tss）
            # plaintext 用于实际的延迟计算
            for name in ("ciphertext", "plaintext"):
                if msg.from_client:
                    # 客户端 -> 服务器，使用客户端连接信息
                    data = {
                        'peername': flow.client_conn.peername,
                        'sockname': flow.client_conn.sockname,
                        'payload': payload_b64,
                        'direction': direction,
                        'ts': ts,
                    }
                else:
                    # 服务器 -> 客户端，使用服务器连接信息
                    data = {
                        'peername': flow.server_conn.peername,
                        'sockname': flow.server_conn.sockname,
                        'payload': payload_b64,
                        'direction': direction,
                        'ts': ts,
                    }
                self.pipe.write(name, data)

    def tcp_end(self, flow):
        """TCP 连接结束"""
        key = self._get_flow_key(flow)
        self._flow_start_time.pop(key, None)
        self._server_info.pop(key, None)
