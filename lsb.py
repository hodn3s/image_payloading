import sys
import struct
import numpy
import matplotlib.pyplot as plt
from PIL import Image
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

# -------------------------
# AES encryption class
# -------------------------
class AESCipher:
    def __init__(self, key):
        self.bs = 32  # Block size
        self.key = hashlib.sha256(key.encode()).digest()  # 32-byte digest

    def encrypt(self, raw):
        raw_bytes = self._pad(raw)  # pad returns bytes
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw_bytes)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[AES.block_size:])
        return self._unpad(decrypted)

    def _pad(self, s):
        if isinstance(s, str):
            s = s.encode()  # Convert string to bytes
        padding_len = self.bs - len(s) % self.bs
        padding = bytes([padding_len] * padding_len)
        return s + padding

    @staticmethod
    def _unpad(s):
        padding_len = s[-1]
        return s[:-padding_len]

# -------------------------
# LSB Steganography functions
# -------------------------

def decompose(data):
    """Convert bytes into list of bits"""
    v = []
    fSize = len(data)
    bytes_list = list(struct.pack("i", fSize))
    bytes_list += list(data)
    for b in bytes_list:
        for i in range(7, -1, -1):
            v.append((b >> i) & 1)
    return v

def assemble(v):
    """Convert list of bits back into bytes"""
    bytes_out = bytearray()
    length = len(v)
    for idx in range(0, len(v)//8):
        byte = 0
        for i in range(8):
            if idx*8 + i < length:
                byte = (byte << 1) + v[idx*8 + i]
        bytes_out.append(byte)
    payload_size = struct.unpack("i", bytes_out[:4])[0]
    return bytes_out[4: payload_size + 4]

def set_bit(n, i, x):
    mask = 1 << i
    n &= ~mask
    if x:
        n |= mask
    return n

def embed(imgFile, payload, password):
    img = Image.open(imgFile)
    width, height = img.size
    conv = img.convert("RGBA")
    conv_data = conv.load()
    print("[*] Input image size: %dx%d pixels." % (width, height))
    max_size = width * height * 3.0 / 8 / 1024
    print("[*] Usable payload size: %.2f KB." % max_size)

    with open(payload, "rb") as f:
        data = f.read()
    print("[+] Payload size: %.3f KB " % (len(data)/1024.0))

    cipher = AESCipher(password)
    data_enc = cipher.encrypt(data)

    v = decompose(data_enc)
    while len(v) % 3:
        v.append(0)

    payload_size = len(v)/8/1024.0
    print("[+] Encrypted payload size: %.3f KB " % payload_size)
    if payload_size > max_size - 4:
        print("[-] Cannot embed. File too large")
        sys.exit()

    steg_img = Image.new('RGBA', (width, height))
    data_img = steg_img.load()

    idx = 0
    for h in range(height):
        for w in range(width):
            r, g, b, a = conv_data[w, h]
            if idx < len(v):
                r = set_bit(r, 0, v[idx])
                g = set_bit(g, 0, v[idx+1])
                b = set_bit(b, 0, v[idx+2])
            data_img[w, h] = (r, g, b, a)
            idx += 3

    steg_img.save(imgFile + "-stego.png", "PNG")
    print("[+] %s embedded successfully!" % payload)

def extract(in_file, out_file, password):
    img = Image.open(in_file)
    width, height = img.size
    conv_data = img.convert("RGBA").load()
    print("[+] Image size: %dx%d pixels." % (width, height))

    v = []
    for h in range(height):
        for w in range(width):
            r, g, b, a = conv_data[w, h]
            v.append(r & 1)
            v.append(g & 1)
            v.append(b & 1)

    data_out = assemble(v)

    cipher = AESCipher(password)
    data_dec = cipher.decrypt(data_out)

    with open(out_file, "wb") as out_f:
        out_f.write(data_dec)

    print("[+] Written extracted data to %s." % out_file)

def analyse(in_file):
    BS = 100
    img = Image.open(in_file)
    width, height = img.size
    print("[+] Image size: %dx%d pixels." % (width, height))
    conv_data = img.convert("RGBA").load()

    vr, vg, vb = [], [], []
    for h in range(height):
        for w in range(width):
            r, g, b, a = conv_data[w, h]
            vr.append(r & 1)
            vg.append(g & 1)
            vb.append(b & 1)

    avgR, avgG, avgB = [], [], []
    for i in range(0, len(vr), BS):
        avgR.append(numpy.mean(vr[i:i + BS]))
        avgG.append(numpy.mean(vg[i:i + BS]))
        avgB.append(numpy.mean(vb[i:i + BS]))

    blocks = list(range(len(avgR)))
    plt.axis([0, len(avgR), 0, 1])
    plt.ylabel('Average LSB per block')
    plt.xlabel('Block number')
    plt.plot(blocks, avgB, 'bo')
    plt.show()

def usage(progName):
    print("LSB steganography. Hide files within least significant bits of images.\n")
    print("Usage:")
    print("  %s hide <img_file> <payload_file> <password>" % progName)
    print("  %s extract <stego_file> <out_file> <password>" % progName)
    print("  %s analyse <stego_file>" % progName)
    sys.exit()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage(sys.argv[0])

    if sys.argv[1] == "hide":
        embed(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "extract":
        extract(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "analyse":
        analyse(sys.argv[2])
    else:
        print("[-] Invalid operation specified")
