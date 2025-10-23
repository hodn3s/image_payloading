import sys
import struct
import numpy
import matplotlib.pyplot as plt
from PIL import Image
from crypt import AESCipher  # ensure this file exists with AESCipher class


# --- Helper Functions ---

def decompose(data):
    v = []
    fSize = len(data)
    bytes_arr = list(struct.pack("i", fSize)) + list(data)
    for b in bytes_arr:
        for i in range(7, -1, -1):
            v.append((b >> i) & 0x1)
    return v


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


def set_bit(n, i, x):
    mask = 1 << i
    n &= ~mask
    if x:
        n |= mask
    return n


# --- Core Steganography Functions ---

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


# --- Improved Analysis ---


import numpy as np
import matplotlib.pyplot as plt
import cv2

def analyse(original_path, stego_path):
    original = cv2.imread(original_path, cv2.IMREAD_COLOR)
    stego = cv2.imread(stego_path, cv2.IMREAD_COLOR)

    if original is None or stego is None:
        raise ValueError("One or both images could not be read. Check the file paths.")

    # Convert to grayscale for analysis
    gray_original = cv2.cvtColor(original, cv2.COLOR_BGR2GRAY)
    gray_stego = cv2.cvtColor(stego, cv2.COLOR_BGR2GRAY)

    # LSB differences
    lsb_diff = np.bitwise_xor(gray_original, gray_stego) & 1
    diff = cv2.absdiff(gray_original, gray_stego)

    # Coordinates of changed LSBs
    y_coords, x_coords = np.where(lsb_diff > 0)

    # --- Plot setup ---
    fig, axs = plt.subplots(1, 3, figsize=(18, 6))

    # Original Image Scatter
    axs[0].imshow(cv2.cvtColor(original, cv2.COLOR_BGR2RGB))
    axs[0].set_title("Original Image Scatter")
    axs[0].axis("off")

    # Stego Image Scatter
    axs[1].imshow(cv2.cvtColor(stego, cv2.COLOR_BGR2RGB))
    axs[1].set_title("Stego Image Scatter")
    axs[1].axis("off")

    # Difference Scatter (Combined Overlay)
    axs[2].imshow(np.zeros_like(gray_original), cmap='gray')
    axs[2].set_title("Difference Scatter (Overlay of Original + Stego)")
    axs[2].invert_yaxis()

    # Scatter: Original in Blue, Stego in Red
    axs[2].scatter(x_coords, y_coords, c='blue', s=5, alpha=0.4, label='Original (LSB=0)')
    axs[2].scatter(x_coords, y_coords, c='red', s=5, alpha=0.4, label='Stego (LSB=1)')

    # Overlay using difference intensity
    axs[2].imshow(diff, cmap='hot', alpha=0.5)

    axs[2].legend(loc='upper right', fontsize=8)
    plt.tight_layout()
    plt.show()



def lsb_diff_heatmap(original_path, stego_path, output_path="lsb_heatmap_full_comparison.png"):
    import cv2
    import numpy as np
    import matplotlib.pyplot as plt
    import seaborn as sns

    # Load images
    orig = cv2.imread(original_path)
    steg = cv2.imread(stego_path)

    if orig is None or steg is None:
        raise FileNotFoundError("❌ One or both images could not be loaded. Check file paths.")
    if orig.shape != steg.shape:
        raise ValueError("❌ Original and stego images must have identical dimensions.")

    # Convert to grayscale for heatmap and difference
    orig_gray = cv2.cvtColor(orig, cv2.COLOR_BGR2GRAY)
    steg_gray = cv2.cvtColor(steg, cv2.COLOR_BGR2GRAY)

    # Compute absolute / LSB differences
    diff_abs = cv2.absdiff(orig_gray, steg_gray)
    lsb_diff = np.bitwise_xor(orig_gray, steg_gray) & 1

    # Coordinates of changed pixels
    y_coords, x_coords = np.where(diff_abs > 0)

    # --- Plot ---
    fig, axs = plt.subplots(1, 4, figsize=(24, 6))

    # 1️⃣ Original image (actual photo)
    axs[0].imshow(cv2.cvtColor(orig, cv2.COLOR_BGR2RGB))
    axs[0].set_title("Original Image")
    axs[0].axis("off")

    # 2️⃣ Stego heatmap with differences marked
    sns.heatmap(steg_gray, ax=axs[1], cmap="viridis", cbar=True)
    axs[1].scatter(x_coords, y_coords, facecolors='none', edgecolors='red', s=10, linewidths=0.5, label='Differences')
    axs[1].set_title("Stego Heatmap (Differences Marked)")
    axs[1].axis("off")
    axs[1].legend(loc='upper right', fontsize=8)

    # 3️⃣ Difference heatmap
    sns.heatmap(diff_abs, ax=axs[2], cmap="hot", cbar=True)
    axs[2].set_title("Absolute / LSB Difference Heatmap")
    axs[2].axis("off")

    # 4️⃣ Output stego image (exact photo after embedding payload)
    axs[3].imshow(cv2.cvtColor(steg, cv2.COLOR_BGR2RGB))
    axs[3].set_title("Stego Image (Actual Payload Result)")
    axs[3].axis("off")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.show()

    print(f"✅ Full heatmap & image comparison saved to: {output_path}")



# --- Command-Line Interface ---

def usage(progName):
    print("LSB steganography tool — hide files in images via least significant bits.\n")
    print("Usage:")
    print(f"  {progName} hide <img_file> <payload_file> <password>")
    print(f"  {progName} extract <stego_file> <out_file> <password>")
    print(f"  {progName} analyse <image_file> [block_size]")
    print(f"  {progName} heatmap <original_img> <stego_img>")
    sys.exit()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage(sys.argv[0])

    cmd = sys.argv[1]

    if cmd == "hide":
        embed(sys.argv[2], sys.argv[3], sys.argv[4])

    elif cmd == "extract":
        extract(sys.argv[2], sys.argv[3], sys.argv[4])

    elif cmd == "analyse":
        block_size = int(sys.argv[3]) if len(sys.argv) > 3 else 5000
        analyse(sys.argv[2], block_size)

    elif cmd == "heatmap":
        if len(sys.argv) < 4:
            print("Usage: python lsb.py heatmap <original_img> <stego_img>")
            sys.exit()
        lsb_diff_heatmap(sys.argv[2], sys.argv[3])

    else:
        print("[-] Invalid operation specified")
        usage(sys.argv[0])
