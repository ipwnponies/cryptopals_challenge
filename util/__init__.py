import random

from Crypto.Cipher import AES


def brute_force_byte_key(message):
    results = []
    # Byte key size range is 256 possible keys
    for key in range(256):
        candidate = bytes([i ^ key for i in message])
        results.append((_score_english(candidate), candidate, key))
    return results


def _score_english(message):
    '''Calculate naive score for presence of common English letters.

    This uses a naive heuristic to score a message. It assigns an unweighted value when a common
    English letter is detected.
    '''
    common_letters = 'ETAOIN SHRDLU'
    return sum(1 for i in message if chr(i).upper() in common_letters)


def decrypt_rotating_bytekey(message, key):
    # Use modulo to circularly get applicable byte from key
    return bytes(char ^ key[index % len(key)] for index, char in enumerate(message))


def chunk(message, chunk_size):
    result = []
    for index in range(0, len(message), chunk_size):
        result.append(message[index:index + chunk_size])
    return result


def decrypt_ecb(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(message)


def xor(value1, value2):
    assert len(value1) == len(value2)
    return bytes(a ^ b for a, b in zip(value1, value2))


def pkcs_padding(message, chunk_size):
    '''Pad the message at the end with \x04 characters to get even block sizes.

    This is not real implementation of pkcs7 padding: https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7.
    It's extremely flawed but sufficiently serves the purpose of learning cryptography.
    Namely, there's no way to tell if your last byte is padding or plaintext is even multiple of blocksize.
    '''
    chunked = chunk(message, chunk_size)
    chunked[-1] = chunked[-1].ljust(chunk_size, b'\x04')
    return b''.join(chunked)


def generate_random_bytes(size):
    return bytes([_random_byte() for i in range(size)])


def _random_byte():
    return random.randint(0, 255)


def detect_ecb(message):
    '''Extremely naive detection of ECB cipher.

    Under ECB scheme, the same block (character) will be enrypted to the same value, we can do a
    simple distinct (set) algorithm.
    '''
    chunks = chunk(message, 16)
    return len(chunks) != len(set(chunks))


def detect_block_size(key, oracle):
    '''Detect blocksize of encryption function.

    Determines the block size used in encryption scheme. It passes in known common plaintext and
    determines when the output blocks begin to repeat.
    '''
    blocksize = 0
    for pad_length in range(1, 2**6):
        ciphertext = oracle('a' * pad_length, key)

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
