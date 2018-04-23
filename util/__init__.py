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
    '''Pad the message at the end with \x04 characters to get even block sizes.'''
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
