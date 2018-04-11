import codecs

from Crypto.Cipher import AES

from set2.challenge11 import generate_random_bytes
from set2.challenge9 import pkcs_padding
from util import chunk


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


def detect_block_size(key):
    '''Detect blocksize of encryption function.

    Determines the block size used in encryption scheme. It passes in known common plaintext and
    determines when the output blocks begin to repeat.
    '''
    blocksize = 0
    for pad_length in range(1, 2**6):
        ciphertext = encryption_oracle(b'a' * pad_length, key)

        # Split the cipher text into blocks of even size
        for j in range(len(ciphertext)//2, 1, -1):

            # Skip non-divisible sizes
            if len(ciphertext) % j != 0:
                continue

            chunks = chunk(ciphertext, j)
            if len(chunks) != len(set(chunks)):
                # If there are repeated blocks, this is a candiate size
                blocksize = j
                break
        if blocksize:
            break
    else:
        raise Exception('Could not detect block size')

    return blocksize


def detect_message_length(key):
    '''Detect length of secret message

    This is done by adding plaintext to fill-in the padding and counting how many bytes was needed.
    '''
    pad_length = 0
    ciphertext_length = 0

    # Safety terminate limit
    max_padding_limit = 100
    for _ in range(max_padding_limit):
        ciphertext = encryption_oracle(b'\x00' * pad_length, key)
        if ciphertext_length and ciphertext_length != len(ciphertext):
            # Decrement to account for overshoot
            pad_length -= 1
            break
        else:
            ciphertext_length = len(ciphertext)
            pad_length += 1
    else:
        raise Exception('Could not detect reasonable message length')

    return ciphertext_length - pad_length


def main():
    key = generate_random_bytes(16)

    blocksize = detect_block_size(key)
    assert blocksize == 16, 'ECB uses 16 byte blocks, detected blocksize of {}'.format(blocksize)

    message_length = detect_message_length(key)
    assert message_length == 138


if __name__ == '__main__':
    main()
