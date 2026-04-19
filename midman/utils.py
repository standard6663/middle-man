import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def is_cert_valid(cert_path: str) -> bool:
    """
    检查证书是否有效
    """
    if os.path.exists(cert_path):
        with open(cert_path, "rb") as f:
            pem_data = f.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        return 'midman' not in f"{cert.subject}_{cert.issuer}"
    return False
