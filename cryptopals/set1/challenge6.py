
import base64
import cipher_lib


def b64decode_from_file(file) -> bytes:
    with open(file) as f:
        encoded = ""
        for line in f.readlines():
            encoded += line.strip("\n")

        cipher = base64.b64decode(encoded)
        return cipher


cipher = b64decode_from_file("./challenge6.txt")


(key, cleartext) = cipher_lib.bruteforce_repeating_key_xor(cipher)
print("Key is: " + key)
print("\n")
print("Decrypted ciphertext: " + cleartext)
