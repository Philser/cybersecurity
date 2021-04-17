import cipher_lib

with open("./challenge4.txt") as f:
    scores_global = []
    for string in f.readlines():
        raw_bytes = bytes.fromhex(string.strip('\n'))
        scores_local = []
        try:
            for character in range(32, 123):  # ASCII codes for A..Z
                output = cipher_lib.decipher_single_byte_xor(
                    raw_bytes, character)
                score = cipher_lib.calculate_chi_squared(output.upper())
                scores_local.append((score, chr(character), output))

            scores_local.sort()
            # Only look at the most likely solution for every string
            # scores_global.append(scores_local[0])
            # scores_global.append(scores_local[1])
            # scores_global.append(scores_local[2])
            scores_global.append(scores_local[0])
        except UnicodeDecodeError:
            # could not decode string, continue with next
            continue

scores_global.sort()
print("Results:")
print(scores_global)
# for i in scores_global:
#     for j in i:
#         print(j)
