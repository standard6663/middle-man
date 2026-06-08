import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hash_sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def aes_gcm_encrypt(key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    assert len(key) == 16, "Key must be 16 bytes for AES-128"
    assert len(nonce) == 12, "Nonce must be 12 bytes for AES-GCM"
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, None)

def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    assert len(key) == 16, "Key must be 16 bytes for AES-128"
    assert len(nonce) == 12, "Nonce must be 12 bytes for AES-GCM"
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def calc_nonce(basic: bytes, ctr: bytes) -> bytes:
    assert len(basic) == 12, "Basic nonce must be 12 bytes for AES-GCM"
    assert len(ctr) == 8, "Counter must be 8 bytes for AES-GCM"
    n = bytearray(basic)
    for i in range(8):
        n[i + 4] ^= ctr[i]
    return bytes(n)


if __name__ == "__main__":
    import struct
    secret = b'secret'
    print(f"secret:\t{secret.hex()}")
    mk = hash_sha256(secret)
    print(f"mk:\t{mk.hex()}")

    randc = b'\x01' * 16
    randm = b'\x02' * 16
    print(f"randc:\t{randc.hex()}")
    print(f"randm:\t{randm.hex()}")    

    salt = randc + randm
    print(f"salt:\t{salt.hex()}")
    mac = hmac_sha256(mk, salt)
    print(f"hamc:\t{mac.hex()}")
    sk = mac[0:16]
    print(f"sk:\t{sk.hex()}")
    nonce = mac[16:28]
    print(f"nonce:\t{nonce.hex()}")
    ctr = struct.pack('>Q', 1) # 8 bytes
    print(f"ctr:\t{ctr.hex()}")

    n = calc_nonce(nonce, ctr)
    print(f"n:\t{n.hex()}")
    plaintext = b'plaintext' + b'\x01' * (16 - len(b'plaintext'))
    print(f"plaintext:\t{plaintext.hex()}")
    ciphertext = aes_gcm_encrypt(sk, plaintext, n)
    print(f"ciphertext:\t{ciphertext.hex()}")
    decrypted = aes_gcm_decrypt(sk, ciphertext, n)
    print(f"decrypted:\t{decrypted.hex()}")
