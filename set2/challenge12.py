import codecs

from Crypto.Cipher import AES

from set2.challenge11 import generate_random_bytes
from set2.challenge9 import pkcs_padding


def encryption_oracle(message, key):
    unknown_string = codecs.decode((
        'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIG'
        'Rvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll'
        'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ'
        'pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    ).encode(), 'base64')
    message = pkcs_padding(message + unknown_string, 16)

    cipher_mode = AES.MODE_ECB
    cipher = AES.new(key, cipher_mode)

    return cipher.encrypt(message)


def main():
    key = generate_random_bytes(16)
    print(key)


if __name__ == '__main__':
    main()
