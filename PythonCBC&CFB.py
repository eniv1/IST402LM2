import sys

# Helper functions
def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def pad_bytes(msg, block_size):
    padding_len = block_size - (len(msg) % block_size)
    padding = bytes([padding_len] * padding_len)
    return msg + padding

def unpad_bytes(msg, block_size):
    padding_len = msg[-1]
    if padding_len > block_size or any(msg[-i] != padding_len for i in range(1, padding_len + 1)):
        raise ValueError("Invalid padding")
    return msg[:-padding_len]

# Block cipher function
def encrypt_block(block, key):
    if len(block) != len(key):
        raise ValueError("Block and key sizes must match")
    return xor_bytes(block, key)

def decrypt_block(block, key):
    if len(block) != len(key):
        raise ValueError("Block and key sizes must match")
    return xor_bytes(block, key)

# CBC encryption and decryption
def cbc_encrypt(msg, key, iv):
    block_size = len(key)
    msg = pad_bytes(msg, block_size)
    ciphertext = b""
    prev_block = iv
    for i in range(0, len(msg), block_size):
        block = msg[i:i+block_size]
        block = xor_bytes(block, prev_block)
        prev_block = encrypt_block(block, key)
        ciphertext += prev_block
    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    block_size = len(key)
    plaintext = b""
    prev_block = iv
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        decrypted_block = decrypt_block(block, key)
        decrypted_block = xor_bytes(decrypted_block, prev_block)
        plaintext += decrypted_block
        prev_block = block
    return unpad_bytes(plaintext, block_size)

# CFB encryption and decryption
def cfb_encrypt(msg, key, iv):
    block_size = len(key)
    ciphertext = b""
    prev_block = iv
    for i in range(len(msg)):
        keystream = encrypt_block(prev_block, key)[:1]
        ciphertext += bytes([msg[i] ^ keystream[0]])
        prev_block = prev_block[1:] + keystream
    return ciphertext

def cfb_decrypt(ciphertext, key, iv):
    block_size = len(key)
    plaintext = b""
    prev_block = iv
    for i in range(len(ciphertext)):
        keystream = encrypt_block(prev_block, key)[:1]
        plaintext += bytes([ciphertext[i] ^ keystream[0]])
        prev_block = prev_block[1:] + bytes([ciphertext[i]])
    return plaintext


def main():
    print("Enter the plaintext:")
    plaintext = input().encode()
    key = b"abcdefghijklmnop"
    iv = b"1234567890123456"

    print("CBC encryption:")
    ciphertext = cbc_encrypt(plaintext, key, iv)
    print("Ciphertext:", ciphertext.hex())
    decrypted_plaintext = cbc_decrypt(ciphertext, key, iv)
    print("Decrypted plaintext:", decrypted_plaintext.decode())

    print("CFB encryption:")
    ciphertext = cfb_encrypt(plaintext, key, iv)
    print("Ciphertext:", ciphertext.hex())
    decrypted_plaintext = cfb_decrypt(ciphertext, key, iv)
    print("Decrypted plaintext:", decrypted_plaintext.decode())

if __name__ == "__main__":
    main()
