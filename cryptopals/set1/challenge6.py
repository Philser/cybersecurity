
import base64
import cipher_lib


def decode_from_file(file):
    with open(file) as f:
        encoded = ""
        for line in f.readlines():
            encoded += line.strip("\n")

        cipher = base64.b64decode(encoded)
        return cipher


def guess_keysize(cipher):
    distances = []
    for keysize_guess in range(2, 41):
        distance = 0
        # Average it for better results
        offset = 0
        i = 0
        while offset < len(cipher):
            bytes1 = cipher[offset: offset + keysize_guess]
            bytes2 = cipher[offset + keysize_guess: offset + keysize_guess * 2]
            if (len(bytes1) != len(bytes2)):
                # reached end, ignore last dangling bytes for now
                break
            dist = cipher_lib.get_hamming_distance(
                bytes1,
                bytes2
            )
            distance += dist / keysize_guess  # normalize
            i += 1
            offset = keysize_guess * i * 2

        average = distance / i
        distances.append((keysize_guess, average))

    distances.sort(key=lambda distance: distance[1])
    print(distances)
    # We only care for the keysize with the lowest distance
    return distances[0][0]


def slice_by_keysize(cipher, key_size):
    cipher_blocks = []
    offset = 0
    i = 0
    while offset < len(cipher):
        cipher_blocks.append(cipher[offset: offset + key_size])
        i += 1
        offset = key_size * i
    return cipher_blocks


def transpose_blocks(cipher_blocks, key_size):
    transposed = []
    for i in range(0, key_size):
        transposed.append(b"")
        for j in range(0, len(cipher_blocks)):
            transposed[i] += cipher_blocks[j][i].to_bytes(
                1, byteorder='big')

    return transposed


def decrypt_repeating_key_xor(cipher, key):
    spread_key = ""
    for i in range(0, len(cipher)):
        spread_key += key[i % len(key)]

    cleartext = ""
    for index in range(0, len(cipher)):
        deciphered = cipher[index] ^ spread_key.encode('ascii')[index]
        cleartext += deciphered.to_bytes(
            1, byteorder='big').decode('ascii')

    return cleartext


cipher = decode_from_file("./challenge6.txt")

key_size = guess_keysize(cipher)

cipher_blocks = slice_by_keysize(cipher, key_size)

# TODO: Ignore for now, later fix that
# TODO: Need to find a way to deal with the last block that is usually not
#       of keysize length
cipher_blocks = cipher_blocks[0:len(cipher_blocks) - 1]

transposed = transpose_blocks(cipher_blocks, key_size)

key = ""

for block in transposed:
    block_scores = []
    for character in range(32, 123):
        output = cipher_lib.decipher_single_byte_xor(block, character)
        score = cipher_lib.score_plaintext(output.upper())
        block_scores.append((score, chr(character), output))
    block_scores.sort()
    key += block_scores[0][1]

print("Key is probably: " + key)

cleartext = decrypt_repeating_key_xor(cipher, key)
print(cleartext)
