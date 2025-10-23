import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher:

    def __init__(self, key):
        self.bs = 32  # Block size
        self.key = hashlib.sha256(key.encode()).digest()  # 32-byte digest

    def encrypt(self, raw):
        if isinstance(raw, str):
            raw = raw.encode('utf-8')  # convert string to bytes
        padded = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(padded)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[AES.block_size:])
        return self._unpad(decrypted)

    def _pad(self, b):
        # Pad with bytes
        pad_len = self.bs - len(b) % self.bs
        return b + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(b):
        pad_len = b[-1]
        return b[:-pad_len]
