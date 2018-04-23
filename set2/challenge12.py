import codecs

from Crypto.Cipher import AES

from util import chunk
from util import generate_random_bytes
from util import pkcs_padding


def encryption_oracle(message, key):
    '''Encryption function with secret payload.'''
    unknown_string = codecs.decode(
        (
            'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIG'
            'Rvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll'
            'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ'
            'pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
        ).encode(), 'base64',
    )
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


def extract_message(blocksize, key, message_length):
    '''Extract the secret message in encryption function.

    Pass to encryption function padding and detect the last significant byte.
    Then increase padding and detect the next byte.
    Repeat until whole block is detected.
    Shift to next block and repeat algorithm.
    '''
    block_offset = 0
    partial_block_decrypted_bytes = []

    # Keep decrypting while we know the hidden message's length
    while len(partial_block_decrypted_bytes) < message_length:
        # Add known padtext to detect last byte of a block, decreasing the padding every iteration
        for padding_lengthj in range(blocksize - 1, -1, -1):
            # Set the pad text to 1 byte less than blocksize. This will force the first block to include the
            # hidden message in LSB
            padtext = b'A' * padding_lengthj

            lsb = extract_lsb(block_offset, blocksize, key, padtext, bytes(partial_block_decrypted_bytes))
            partial_block_decrypted_bytes.append(lsb)
        # Move on to the next block. No need to increase padding, we are looking at the bytes of
        # next block and already know all the bytes + padtext of previous blocks
        block_offset += 1

    # Strip out the pkcs padding to get the sanitized message
    return bytes(partial_block_decrypted_bytes[:message_length])


def extract_lsb(block_offset, blocksize, key, known_padtext, partial_decrypt):
    '''Get the LSB of a block.

    Brute force decrypt a single byte of the block by generating all possible values into a rainbow
    table.
    First we generate the ciphertext, witb padding.
    Then we generate a rainbow table for the next unknown byte. Pad the plaintext with padding +
    partially decrypted plaintext.
    '''
    start = block_offset * blocksize
    end = start + blocksize

    # Reverse lookup from all generated possibiities
    rainbow_table = {
        encryption_oracle(known_padtext + partial_decrypt + chr(i).encode(), key)[start:end]:
        i
        for i in range(256)
    }

    ciphertext = encryption_oracle(known_padtext, key)
    return rainbow_table[ciphertext[start:end]]


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

    # blocksize = detect_block_size(key)
    # assert blocksize == 16, 'ECB uses 16 byte blocks, detected blocksize of {}'.format(blocksize)

    # Hard code blocksize, we know it's ECB
    blocksize = 16

    message_length = detect_message_length(key)
    assert message_length == 138

    message = extract_message(blocksize, key, message_length)
    assert message == b'''Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
'''


if __name__ == '__main__':
    main()
