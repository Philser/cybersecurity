def decipher_single_byte_xor(cipher, key):
    output = ""
    for byte_index in range(0, len(cipher)):
        deciphered = cipher[byte_index] ^ key
        text = deciphered.to_bytes(
            1, byteorder='big').decode('ascii')
        output += text
    return output

# Sources:
# https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
# https://en.wikipedia.org/wiki/Chi-squared_test
# https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html


def calculate_chi_squared(str):
    english_frequency_percent = {
        'E': 11.1607, 'A': 8.4966, 'R': 7.5809,
        'I': 7.5448, 'O': 7.1635, 'T': 6.9509,
        'N': 6.6544, 'S': 5.7351, 'L': 5.4893,
        'C': 4.5388, 'U': 3.6308, 'P': 3.1671,
        'M': 3.0129, 'H': 3.0034, 'G': 2.4705,
        'B': 2.0720, 'F': 1.8121, 'Y': 1.7779,
        'W': 1.2899, 'K': 1.1016, 'V': 1.0074,
        'X': 0.2902, 'Z': 0.2722, 'J': 0.1965,
        'Q': 0.1962, 'D': 3.3844
    }

    distr = get_frequency_distribution(str)

    chi_squared = 0.0
    for character in distr:
        observed = distr[character]
        expected = english_frequency_percent[character] / 100.0 * len(str)
        s = observed - expected
        chi_squared += s ** 2 / expected

    return chi_squared


def get_frequency_distribution(str):
    character_frequency = {}

    for character in str:
        upperCase = character.upper()
        if ord(upperCase) < 65 or ord(upperCase) > 90:  # Only accept letters
            continue  # ignore NUL bytes and other
        if character in character_frequency:
            character_frequency[upperCase] += 1
        else:
            character_frequency[upperCase] = 1

    return character_frequency


raw_bytes = bytes.fromhex("1b37373331363f78151b7f2b783431333d7839782"
                          "8372d363c78373e783a393b3736")
scores = []
for character in range(65, 91):  # ASCII codes for A..Z
    output = decipher_single_byte_xor(raw_bytes, character)
    scores.append((calculate_chi_squared(output.upper()),
                   chr(character), output))

scores.sort()

print("Most likely solutions:")
print(scores[0])
print(scores[1])
print(scores[2])
