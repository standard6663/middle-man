from mitmproxy import ctx
from midman.pipe import PipeWriter
from mitmproxy import http


class Record:
    def __init__(self) -> None:
        self.pipe = PipeWriter(ctx.options.pipe_path)
        self.request_start = None
        self.request_end = None
        self.response_start = None
        self.response_end = None

    # def tls_clienthello(self, tls_clienthello):
    #     context = tls_clienthello.context
    #     self.pipe = PipeWriter(context.options.pipe_path)

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

    def response(self, flow: http.HTTPFlow):
        conn = flow.server_conn
        data = {
            'peername': conn.peername,
            'sockname': conn.sockname,
            'cipher_suite': conn.cipher,
            'protocol_version': conn.tls_version,
            'alpn': conn.alpn.decode() if conn.alpn else ""
        }
        self.pipe.write("response", data)

    def client_connected(self, client):
        # data = {
        #     "status": "start",
        #     "internal_peer": client.peername,
        #     "internal_sock": client.sockname,
        #     "ts_start": client.timestamp_start,
        # }
        # self.pipe.write("session", data)
        pass

    def client_disconnected(self, client):        
        data = {
            "status": "end",
            "internal_peer": client.peername,
            "internal_sock": client.sockname,
            "ts_end": client.timestamp_end,
        }

        self.pipe.write("session", data)

    def server_connected(self, conn):
        # client = conn.client
        # server = conn.server
        # data = {
        #     "status": "connected",
        #     "internal_peer": client.peername,
        #     "internal_sock": client.sockname,
        #     "external_sni": server.sni,
        #     "external_peer": server.peername,
        #     "external_sock": server.sockname,
        # }
        # self.pipe.write("session", data)
        pass

