import importlib.util
spec = importlib.util.spec_from_file_location("cipher_lib", "../lib/cipher_lib.py")
cipher_lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cipher_lib)
from Crypto.Cipher import AES

key = b"YELLOW SUBMARINE"
suite = AES.new(key, AES.MODE_ECB)
enc = suite.encrypt(cipher_lib.pad_pkcs7("YELLOW SUBMARINE", 16).encode())
dec = suite.decrypt(enc)

print (dec)