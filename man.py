import sys

# 密码套件轮换 addon
_counter = 0
_ciphers_a = "ECDHE-RSA-AES128-GCM-SHA256"
_ciphers_b = "ECDHE-RSA-CHACHA20-POLY1305"


class CipherRotate:
    def __init__(self):
        pass

    def tls_start_server(self, tls_start):
        """mitmproxy -> server TLS 握手开始时设置密码套件"""
        global _counter
        _counter += 1
        cipher = _ciphers_a if _counter % 2 == 1 else _ciphers_b
        # 设置到 server 连接，tlsconfig.py 会读取这个值
        tls_start.conn.cipher_list = (cipher,)
        print(f"[CipherRotate] 连接 #{_counter} -> 提供: {cipher}")


# 当 mitmdump 用 -s man.py 加载时，会调用 addons 列表
addons = [CipherRotate()]

# 当直接 python man.py 运行时，启用 mitmdump
if __name__ == "__main__":
    from mitmproxy.tools.main import mitmdump
    mitmdump()
