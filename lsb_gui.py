import os
import struct
import hashlib
import numpy as np
import customtkinter as ctk
import matplotlib.pyplot as plt

from tkinter import filedialog, messagebox
from PIL import Image
from Crypto import Random
from Crypto.Cipher import AES

# ------------------------------
# Folder setup
# ------------------------------
PROJECT_FOLDER = os.path.dirname(os.path.abspath(__file__))
ENCRYPTED_FOLDER = os.path.join(PROJECT_FOLDER, "image", "Encrypted Files")
EXTRACTED_FOLDER = os.path.join(PROJECT_FOLDER, "image", "Extracted Files")
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(EXTRACTED_FOLDER, exist_ok=True)

SIGNATURE = b"LSBENC"

# ------------------------------
# AES Cipher with proper password validation
# ------------------------------
class AESCipher:
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        if isinstance(raw, str):
            raw = raw.encode('utf-8')
        padded = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(padded)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[AES.block_size:])
        try:
            return self._unpad(decrypted)
        except Exception:
            raise ValueError("Incorrect password or corrupted data")

    def _pad(self, b):
        pad_len = self.bs - len(b) % self.bs
        return b + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(b):
        pad_len = b[-1]
        if pad_len < 1 or pad_len > 32:
            raise ValueError("Invalid padding")
        return b[:-pad_len]

# ------------------------------
# LSB Functions
# ------------------------------
def decompose(data):
    v = []
    data = SIGNATURE + data
    bytes_list = list(struct.pack("i", len(data))) + list(data)
    for b in bytes_list:
        for i in range(7, -1, -1):
            v.append((b >> i) & 1)
    return v

def assemble(v):
    bytes_out = bytearray()
    for idx in range(0, len(v)//8):
        byte = 0
        for i in range(8):
            byte = (byte << 1) + v[idx*8+i]
        bytes_out.append(byte)
    payload_size = struct.unpack("i", bytes_out[:4])[0]
    payload = bytes_out[4:payload_size+4]
    if payload[:len(SIGNATURE)] != SIGNATURE:
        raise ValueError("No encrypted payload detected")
    return payload[len(SIGNATURE):]

def set_bit(n, i, x):
    mask = 1 << i
    n &= ~mask
    if x:
        n |= mask
    return n

def is_encrypted(img_path):
    try:
        img = Image.open(img_path).convert("RGBA")
        width, height = img.size
        conv_data = img.load()
        v = []
        max_bits = 32*8
        bits_collected = 0
        for h in range(height):
            for w in range(width):
                r,g,b,a = conv_data[w,h]
                for color in (r,g,b):
                    v.append(color & 1)
                    bits_collected += 1
                    if bits_collected >= max_bits:
                        break
                if bits_collected >= max_bits:
                    break
            if bits_collected >= max_bits:
                break
        byte_array = bytearray()
        for i in range(0, len(v), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) + v[i+j]
            byte_array.append(byte)
        payload_len = struct.unpack("i", byte_array[:4])[0]
        return 0 < payload_len <= width*height*3//8
    except:
        return False

def embed(imgFile, payload, password, progress_callback=None):
    img = Image.open(imgFile)
    width, height = img.size
    conv_data = img.convert("RGBA").load()
    with open(payload,"rb") as f:
        data = f.read()
    cipher = AESCipher(password)
    data_enc = cipher.encrypt(data)
    v = decompose(data_enc)
    while len(v)%3:
        v.append(0)
    steg_img = Image.new("RGBA",(width,height))
    data_img = steg_img.load()
    idx = 0
    total = len(v)
    update_interval = max(1,total//500)
    if progress_callback:
        progress_callback(0,total)
    for h in range(height):
        for w in range(width):
            r,g,b,a = conv_data[w,h]
            if idx < len(v):
                r = set_bit(r,0,v[idx])
                g = set_bit(g,0,v[idx+1])
                b = set_bit(b,0,v[idx+2])
                idx += 3
                if progress_callback and idx % update_interval == 0:
                    progress_callback(idx,total)
            data_img[w,h]=(r,g,b,a)
    if progress_callback:
        progress_callback(total,total)
    output_file=os.path.join(ENCRYPTED_FOLDER,os.path.basename(imgFile)+"-stego.png")
    steg_img.save(output_file)
    return output_file

def extract(in_file, password, progress_callback=None):
    img = Image.open(in_file)
    width, height = img.size
    conv_data = img.convert("RGBA").load()
    v = []
    total = width * height * 3
    idx = 0
    update_interval = max(1, total // 500)
    if progress_callback:
        progress_callback(0, total)
    for h in range(height):
        for w in range(width):
            r,g,b,a = conv_data[w,h]
            v.append(r&1)
            v.append(g&1)
            v.append(b&1)
            idx += 3
            if progress_callback and idx % update_interval == 0:
                progress_callback(idx, total)
    if progress_callback:
        progress_callback(total,total)
    data_out = assemble(v)
    cipher = AESCipher(password)
    data_dec = cipher.decrypt(data_out)  # raises ValueError if wrong password
    payload_name = os.path.splitext(os.path.basename(in_file))[0] + "_payload.txt"
    output_file = os.path.join(EXTRACTED_FOLDER, payload_name)
    with open(output_file, "wb") as f:
        f.write(data_dec)
    return output_file

# ------------------------------
# GUI Setup
# ------------------------------
ctk.set_default_color_theme("green")
ctk.set_appearance_mode("dark")

root = ctk.CTk()
root.title("LSB Steganography GUI")
root.geometry("900x700")

tab_control = ctk.CTkTabview(root)
tab_control.pack(expand=1, fill="both", padx=10, pady=10)
tab_control.add("Hide Payload")
tab_control.add("Extract Payload")
tab_control.add("Analyse Image")

hide_tab = tab_control.tab("Hide Payload")
extract_tab = tab_control.tab("Extract Payload")
analyse_tab = tab_control.tab("Analyse Image")

# ------------------------------
# Helper: Progress update for CTK
# ------------------------------
def update_progressbar(progressbar, idx, total):
    progressbar.set(idx/total)

# ------------------------------
# Hide Tab
# ------------------------------
hide_img_var = ctk.StringVar()
hide_payload_var = ctk.StringVar()
password_var = ctk.StringVar()

def browse_img():
    file=filedialog.askopenfilename(filetypes=[("PNG Images","*.png"),("All Files","*.*")])
    if file:
        hide_img_var.set(file)
        btn_img.configure(text=os.path.basename(file))

def browse_payload():
    file=filedialog.askopenfilename(filetypes=[("All Files","*.*")])
    if file:
        hide_payload_var.set(file)
        btn_payload.configure(text=os.path.basename(file))

def start_hide():
    img_file = hide_img_var.get()
    payload_file = hide_payload_var.get()
    password = password_var.get()
    if not img_file or not payload_file or not password:
        messagebox.showerror("Error","Select image, payload, and enter password")
        return
    def callback(idx,total):
        update_progressbar(progress_hide, idx, total)
        root.update_idletasks()
    out_file = embed(img_file,payload_file,password,progress_callback=callback)
    messagebox.showinfo("Success",f"Encrypted image saved:\n{out_file}")

def clear_hide_tab():
    hide_img_var.set("")
    hide_payload_var.set("")
    password_var.set("")
    btn_img.configure(text="Upload Image")
    btn_payload.configure(text="Upload Payload")
    entry_password.delete(0,"end")
    progress_hide.set(0)

btn_img = ctk.CTkButton(hide_tab, text="Upload Image", command=browse_img)
btn_img.pack(pady=5)
btn_payload = ctk.CTkButton(hide_tab, text="Upload Payload", command=browse_payload)
btn_payload.pack(pady=5)

ctk.CTkLabel(hide_tab, text="Password:").pack(pady=5)
entry_password = ctk.CTkEntry(hide_tab, textvariable=password_var, show="*")
entry_password.pack(pady=5)

btn_start_hide = ctk.CTkButton(hide_tab, text="Start Hiding Payload", command=start_hide)
btn_start_hide.pack(pady=10)
progress_hide = ctk.CTkProgressBar(hide_tab, width=500, height=20, progress_color="#087529")
progress_hide.pack(pady=10)

btn_clear_hide = ctk.CTkButton(hide_tab, text="Clear", command=clear_hide_tab)
btn_clear_hide.pack(pady=5)

# ------------------------------
# Extract Tab
# ------------------------------
extract_file_var = ctk.StringVar()
extract_password_var = ctk.StringVar()

def browse_extract_file():
    file=filedialog.askopenfilename(filetypes=[("PNG Images","*.png"),("All Files","*.*")])
    if file:
        if not is_encrypted(file):
            messagebox.showwarning("Not Encrypted","File not encrypted or no payload")
            btn_extract.configure(state="disabled")
        else:
            extract_file_var.set(file)
            btn_extract.configure(text=os.path.basename(file))
            entry_extract_pass.configure(state="normal")
            btn_extract.configure(state="normal")

def start_extract():
    file = extract_file_var.get()
    password = extract_password_var.get()
    if not file or not password:
        messagebox.showerror("Error","Select file and enter password")
        return
    def callback(idx,total):
        update_progressbar(progress_extract, idx, total)
        root.update_idletasks()
    try:
        out_file = extract(file,password,progress_callback=callback)
        messagebox.showinfo("Success",f"Payload extracted:\n{out_file}")
    except ValueError as e:
        messagebox.showerror("Error", str(e))

def clear_extract_tab():
    extract_file_var.set("")
    extract_password_var.set("")
    btn_extract_file.configure(text="Upload Encrypted File")
    entry_extract_pass.delete(0,"end")
    progress_extract.set(0)
    btn_extract.configure(state="disabled")

btn_extract_file = ctk.CTkButton(extract_tab,text="Upload Encrypted File",command=browse_extract_file)
btn_extract_file.pack(pady=5)
ctk.CTkLabel(extract_tab, text="Enter Password").pack(pady=5)
entry_extract_pass = ctk.CTkEntry(extract_tab,textvariable=extract_password_var,show="*")
entry_extract_pass.pack(pady=5)

btn_extract = ctk.CTkButton(extract_tab,text="Extract Payload",command=start_extract, state="disabled")
btn_extract.pack(pady=10)
progress_extract = ctk.CTkProgressBar(extract_tab, width=500, height=20, progress_color="#087529")
progress_extract.pack(pady=10)

btn_clear_extract = ctk.CTkButton(extract_tab, text="Clear", command=clear_extract_tab)
btn_clear_extract.pack(pady=5)

# ------------------------------
# Analyse Tab
# ------------------------------
analyse_orig_file_var = ctk.StringVar()
analyse_enc_file_var = ctk.StringVar()

def browse_analyse_file(is_original=False):
    file=filedialog.askopenfilename(filetypes=[("PNG Images","*.png"),("All Files","*.*")])
    if not file:
        return
    if is_original:
        analyse_orig_file_var.set(file)
        btn_orig_file.configure(text=os.path.basename(file))
    else:
        if not is_encrypted(file):
            messagebox.showwarning("Not Encrypted","File not encrypted or no payload")
            btn_analyse.configure(state="disabled")
        else:
            analyse_enc_file_var.set(file)
            btn_enc_file.configure(text=os.path.basename(file))
            if analyse_orig_file_var.get():
                btn_analyse.configure(state="normal")

def analyse_lsb(img_path, block_size=8):
    """
    Analyse the least significant bits (LSB) of an image's RGB channels in blocks.
    Returns three lists: avgR, avgG, avgB containing the average LSB per block.
    """
    img = Image.open(img_path).convert("RGBA")
    data = np.array(img)
    avgR, avgG, avgB = [], [], []

    R = data[:,:,0].flatten()
    G = data[:,:,1].flatten()
    B = data[:,:,2].flatten()

    for i in range(0, len(R), block_size):
        avgR.append(np.mean([b&1 for b in R[i:i+block_size]]))
        avgG.append(np.mean([b&1 for b in G[i:i+block_size]]))
        avgB.append(np.mean([b&1 for b in B[i:i+block_size]]))

    return avgR, avgG, avgB

def start_analyse():
    orig_file = analyse_orig_file_var.get()
    enc_file = analyse_enc_file_var.get()
    
    if not orig_file or not enc_file:
        messagebox.showerror("Error","Select both original and encrypted images")
        return

    # Analyze original
    avgR_orig, avgG_orig, avgB_orig = analyse_lsb(orig_file)
    blocks_orig = list(range(len(avgR_orig)))

    # Analyze encrypted
    avgR_enc, avgG_enc, avgB_enc = analyse_lsb(enc_file)
    blocks_enc = list(range(len(avgR_enc)))

    # Create a single figure with two subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))

    # Plot original
    ax1.plot(blocks_orig, avgR_orig, 'r.-', label="Red LSB")
    ax1.plot(blocks_orig, avgG_orig, 'g.-', label="Green LSB")
    ax1.plot(blocks_orig, avgB_orig, 'b.-', label="Blue LSB")
    ax1.set_title("LSB Analysis: Original Image")
    ax1.set_xlabel("Block number")
    ax1.set_ylabel("Average LSB per block")
    ax1.legend()
    ax1.grid(True)

    # Plot encrypted
    ax2.plot(blocks_enc, avgR_enc, 'r.-', label="Red LSB")
    ax2.plot(blocks_enc, avgG_enc, 'g.-', label="Green LSB")
    ax2.plot(blocks_enc, avgB_enc, 'b.-', label="Blue LSB")
    ax2.set_title("LSB Analysis: Encrypted Image")
    ax2.set_xlabel("Block number")
    ax2.set_ylabel("Average LSB per block")
    ax2.legend()
    ax2.grid(True)

    plt.tight_layout()
    plt.show()





def clear_analyse_tab():
    analyse_orig_file_var.set("")
    analyse_enc_file_var.set("")
    btn_orig_file.configure(text="Upload Original Image")
    btn_enc_file.configure(text="Upload Encrypted Image")
    progress_analyse.set(0)
    btn_analyse.configure(state="disabled")

btn_orig_file = ctk.CTkButton(analyse_tab,text="Upload Original Image",command=lambda: browse_analyse_file(True))
btn_orig_file.pack(pady=5)
btn_enc_file = ctk.CTkButton(analyse_tab,text="Upload Encrypted Image",command=lambda: browse_analyse_file(False))
btn_enc_file.pack(pady=5)
btn_analyse = ctk.CTkButton(analyse_tab,text="Start Analysis",command=start_analyse,state="disabled")
btn_analyse.pack(pady=10)
progress_analyse = ctk.CTkProgressBar(analyse_tab, width=500, height=20, progress_color="#087529")
progress_analyse.pack(pady=10)

btn_clear_analyse = ctk.CTkButton(analyse_tab, text="Clear", command=clear_analyse_tab)
btn_clear_analyse.pack(pady=5)

# ------------------------------
root.mainloop()
