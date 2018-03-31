import random

from Crypto.Cipher import AES

from set1.challenge8 import detect_ecb
from set2.challenge9 import pkcs_padding


def _random_byte():
    return random.randint(0, 255)


def generate_random_bytes(size):
    return bytes([_random_byte() for i in range(size)])


def encryption_oracle(message):
    leading_pad = generate_random_bytes(random.randint(5, 10))
    trailing_pad = generate_random_bytes(random.randint(5, 10))

    message = pkcs_padding(leading_pad + message + trailing_pad, 16)

    key = generate_random_bytes(16)

    if random.random() < 0.5 and False:
        iv_value = generate_random_bytes(16)
        cipher_mode = AES.MODE_CBC
        cipher = AES.new(key, cipher_mode, iv_value)
    else:
        cipher_mode = AES.MODE_ECB
        cipher = AES.new(key, cipher_mode)

    return cipher.encrypt(message), key, cipher_mode


def detect_cipher_mode(message):
    return AES.MODE_ECB if detect_ecb(message) else AES.MODE_CBC


def main():
    input_message = b'same message' * 40
    encrypted_message, _, mode = encryption_oracle(input_message)

    assert mode == detect_cipher_mode(encrypted_message)


if __name__ == '__main__':
    main()
