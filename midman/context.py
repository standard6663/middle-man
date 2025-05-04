import os


class Context:
    def __init__(self):
        self.PIPE_PATH = os.environ.get('PIPE_PATH', "/tmp/.midman.pipe")

        self.MIDMAN_CONF = os.environ.get('MIDMAN_CONF', ".midman")
        self.MIDMAN_SECRET = os.environ.get('MIDMAN_SECRET', "midman_secret")
        self.MIDMAN_PORT = int(os.environ.get('MIDMAN_PORT', "12039"))
        self.MIDMAN_CERT_PATH = f"{self.MIDMAN_CONF}/midman-ca.pem"
        self.MIDMAN_LOG_PATH = os.environ.get('MIDMAN_LOG_PATH', "/tmp/midman.log")

        self.DB_HOST = None
        self.DB_PORT = None
        self.DB_NAME = None
        self.DB_USER = None
        self.DB_PASSWORD = None

        self.ROOT_CA_CERT = None
        self.INTERMEDIATE_CA_KEY = None
        self.INTERMEDIATE_CA_CERT = None
