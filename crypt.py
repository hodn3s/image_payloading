from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

class AESCipher:
    def __init__(self, key):
        self.bs = AES.block_size
        # derive a 32-byte key from the password
        self.key = SHA256.new(key.encode('utf-8')).digest()

    def _pad(self, data: bytes) -> bytes:
        pad_len = self.bs - len(data) % self.bs
        return data + bytes([pad_len]) * pad_len

    def _unpad(self, data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt(self, raw: bytes) -> bytes:
        raw = self._pad(raw)
        iv = Random.new().read(self.bs)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc: bytes) -> bytes:
        iv = enc[:self.bs]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[self.bs:])
        return self._unpad(decrypted)
