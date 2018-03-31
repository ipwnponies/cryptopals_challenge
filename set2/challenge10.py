import codecs
import os

from Crypto.Cipher import AES

from util import chunk
from util import decrypt_ecb
from util import xor


def decrypt_cbc(message, iv_value, key):
    chain = [iv_value] + chunk(message, 16)
    result = []
    for index, block in enumerate(chain):
        if index == 0:
            # Skip initialization vector
            continue

        result.append(_decrypt_cbc_block(block, key, chain[index-1]))
    return b''.join(result)


def _decrypt_cbc_block(block, key, previous_block):
    partial_decryption = decrypt_ecb(block, key)

    # This is the 'chain' part of CBC. Simple XOR to previous block, doesn't necessarily have to
    # be the decrypted value of previous block.
    full_decrypt = xor(partial_decryption, previous_block)
    return full_decrypt


def _decrypt_cbc_without_reinventing_the_wheel(message, iv_value, key):
    cipher = AES.new(key, AES.MODE_CBC, iv_value)
    return cipher.decrypt(message)


def main():
    iv_value = b'\x00' * 16
    key = 'YELLOW SUBMARINE'
    with open(os.path.join(os.path.dirname(__file__), 'challenge10_data'), 'rb') as data_set:
        input_text = b''.join(data_set.readlines())
        encrypted_message = codecs.decode(input_text, 'base64')

    homebrew_solution = decrypt_cbc(encrypted_message, iv_value, key)
    crytpolib_solution = _decrypt_cbc_without_reinventing_the_wheel(encrypted_message, iv_value, key)
    assert crytpolib_solution == homebrew_solution


if __name__ == '__main__':
    main()
