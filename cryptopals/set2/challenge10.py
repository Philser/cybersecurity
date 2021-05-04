from Crypto.Cipher import AES
import importlib.util
spec = importlib.util.spec_from_file_location(
    "cipher_lib", "../lib/cipher_lib.py")
cipher_lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cipher_lib)

with open("./challenge10.enc") as f:
    key = b"YELLOW SUBMARINE"
    block_size = 16
    iv = "\x00" * 16

    text = f.read()
    text = cipher_lib.pad_pkcs7(text, block_size)

    print(cipher_lib.decrypt_aes_cbc(text.encode(), iv.encode(), key).decode())
