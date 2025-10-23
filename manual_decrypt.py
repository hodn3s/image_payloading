from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import sys

def decrypt_file(in_file, out_file, password):
    with open(in_file, "rb") as f:
        data = f.read()

    print(f"[+] Total encrypted bytes: {len(data)}")
    iv = data[:16]
    ciphertext = data[16:]

    print(f"[*] First 16 bytes (IV): {iv}")

    # derive AES key from password
    key = SHA256.new(password.encode("utf-8")).digest()

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        # try unpadding safely
        pad_len = decrypted[-1]
        if pad_len < 16:
            decrypted = decrypted[:-pad_len]
        else:
            print("[!] Unusual padding, keeping raw data")

        with open(out_file, "wb") as out:
            out.write(decrypted)

        print(f"[+] Decryption successful. Saved as {out_file}")
    except ValueError as e:
        print(f"[!] AES error: {e}")
        print("[!] Trying to save raw data anyway...")
        with open(out_file, "wb") as out:
            out.write(ciphertext)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python manual_decrypt.py <input> <output> <password>")
        sys.exit(1)
    decrypt_file(sys.argv[1], sys.argv[2], sys.argv[3])
