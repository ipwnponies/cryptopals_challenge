import codecs
import os

from Crypto.Cipher import AES

from util import chunk
from util import decrypt_ecb
from util import xor


def decrypt_cbc(message, iv, key):
    chain = [iv] + chunk(message, 16)
    result = []
    for index, block in enumerate(chain):
        if index == 0:
            continue

        result.append(xor(decrypt_ecb(block, key), chain[index-1]))
    return b''.join(result)


def _decrypt_cbc_without_reinventing_the_wheel(message, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(message)


def main():
    iv = b'\x00' * 16
    key = 'YELLOW SUBMARINE'
    with open(os.path.join(os.path.dirname(__file__), 'challenge2_data'), 'rb') as data_set:
        input_text = b''.join(data_set.readlines())
        encrypted_message = codecs.decode(input_text, 'base64')

    homebrew_solution = decrypt_cbc(encrypted_message, iv, key)
    crytpolib_solution = _decrypt_cbc_without_reinventing_the_wheel(encrypted_message, iv, key)
    assert crytpolib_solution == homebrew_solution


if __name__ == '__main__':
    main()
