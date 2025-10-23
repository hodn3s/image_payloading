import sys
import struct
import numpy
import matplotlib.pyplot as plt
from PIL import Image
from crypt import AESCipher  # ensure this file exists with AESCipher class

# Decompose a binary file into an array of bits
def decompose(data):
    v = []
    fSize = len(data)
    bytes_arr = list(struct.pack("i", fSize)) + list(data)

    for b in bytes_arr:
        for i in range(7, -1, -1):
            v.append((b >> i) & 0x1)
    return v


# Assemble an array of bits into a binary file
def assemble(v):
    bytes_arr = bytearray()
    length = len(v)

    for idx in range(0, length // 8):
        byte = 0
        for i in range(8):
            if idx * 8 + i < length:
                byte = (byte << 1) + v[idx * 8 + i]
        bytes_arr.append(byte)

    payload_size = struct.unpack("i", bytes(bytes_arr[:4]))[0]
    return bytes(bytes_arr[4: payload_size + 4])


# Set the i-th bit of n to x
def set_bit(n, i, x):
    mask = 1 << i
    n &= ~mask
    if x:
        n |= mask
    return n


# Embed payload file into LSB bits of an image
def embed(imgFile, payload, password):
    img = Image.open(imgFile)
    width, height = img.size
    conv = img.convert("RGBA")

    print(f"[*] Input image size: {width}x{height} pixels.")
    max_size = width * height * 3.0 / 8 / 1024
    print(f"[*] Usable payload size: {max_size:.2f} KB.")

    with open(payload, "rb") as f:
        data = f.read()
    print(f"[+] Payload size: {len(data) / 1024.0:.3f} KB")

    cipher = AESCipher(password)
    data_enc = cipher.encrypt(data)

    v = decompose(data_enc)
    while len(v) % 3:
        v.append(0)

    payload_size = len(v) / 8 / 1024.0
    print(f"[+] Encrypted payload size: {payload_size:.3f} KB")

    if payload_size > max_size - 4:
        print("[-] Cannot embed. File too large")
        sys.exit()

    steg_img = Image.new("RGBA", (width, height))
    data_img = steg_img.load()
    conv_data = conv.load()

    idx = 0
    for h in range(height):
        for w in range(width):
            r, g, b, a = conv_data[w, h]
            if idx < len(v):
                r = set_bit(r, 0, v[idx])
                g = set_bit(g, 0, v[idx + 1])
                b = set_bit(b, 0, v[idx + 2])
            data_img[w, h] = (r, g, b, a)
            idx += 3

    steg_img.save(imgFile + "-stego.png", "PNG")
    print(f"[+] {payload} embedded successfully!")


# Extract data embedded into LSB of the input file
def extract(in_file, out_file, password):
    img = Image.open(in_file)
    width, height = img.size
    conv = img.convert("RGBA")

    print(f"[+] Image size: {width}x{height} pixels.")

    v = []
    conv_data = conv.load()

    for h in range(height):
        for w in range(width):
            r, g, b, a = conv_data[w, h]
            v.append(r & 1)
            v.append(g & 1)
            v.append(b & 1)

    data_out = assemble(v)
    print(f"[*] Extracted payload length: {len(data_out)} bytes")
    print(f"[*] First 16 bytes (potential IV): {data_out[:16]}")

    cipher = AESCipher(password)
    data_dec = cipher.decrypt(data_out)

    with open(out_file, "wb") as out_f:
        out_f.write(data_dec)

    print(f"[+] Written extracted data to {out_file}.")


# Statistical analysis of an image to detect LSB steganography
def analyse(in_file):
    BS = 100
    img = Image.open(in_file)
    width, height = img.size
    conv = img.convert("RGBA")

    print(f"[+] Image size: {width}x{height} pixels.")

    vr, vg, vb = [], [], []
    conv_data = conv.load()

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

    numBlocks = len(avgR)
    blocks = list(range(numBlocks))
    plt.axis([0, len(avgR), 0, 1])
    plt.ylabel("Average LSB per block")
    plt.xlabel("Block number")
    plt.plot(blocks, avgB, "bo")
    plt.show()


def usage(progName):
    print("LSB steganography. Hide files within least significant bits of images.\n")
    print("Usage:")
    print(f"  {progName} hide <img_file> <payload_file> <password>")
    print(f"  {progName} extract <stego_file> <out_file> <password>")
    print(f"  {progName} analyse <stego_file>")
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
