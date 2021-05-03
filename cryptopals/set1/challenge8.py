block_length = 16
with open("./challenge8.enc") as f:
    # AES ECB is deterministic
    # Thus, we need to find a ciphertext that has reoccuring strings
    for line in f.readlines():
        blocks = {}
        # if (len(line) % block_length != 0):
        #     # AES operates on 16 byte blocks
        #     continue

        for i in range(0, len(line) // block_length - 1):
            offset = i * block_length
            
            if blocks.get(line[offset:offset + block_length]):
                print("AES detected in string: ")
                print(line)
                break
            else:
                blocks[line[offset:offset + block_length]] = 1