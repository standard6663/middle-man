"""
TLS 1.2 密码套件轮换 addon
- 第 1、3、5... 个连接：提供 AES128-GCM
- 第 2、4、6... 个连接：提供 CHACHA20
"""
from mitmproxy import ctx
from mitmproxy.proxy import tls


_ciphers_a = "ECDHE-RSA-AES128-GCM-SHA256"
_ciphers_b = "ECDHE-RSA-CHACHA20-POLY1305"
_counter = 0


def load(_loader):
    pass


def tls_clienthello(tls_event: tls.ClientHelloData):
    global _counter
    _counter += 1
    # 根据连接序号选择密码套件
    if _counter % 2 == 1:
        cipher = _ciphers_a
    else:
        cipher = _ciphers_b
    # 设置到服务端连接
    server = tls_event.context.server
    if server:
        server.cipher_list = (cipher,)
    ctx.log.info(f"[CipherRotate] 连接 #{_counter} -> 提供密码套件: {cipher}")
