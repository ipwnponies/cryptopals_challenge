import codecs
import os.path
import operator
from collections import namedtuple

from util import brute_force_byte_key
from util import decrypt_rotating_bytekey


def chunk(message, chunk_size):
    result = []
    for index in range(0, len(message), chunk_size):
        result.append(message[index:index + chunk_size])
    return result


def bucket(message, bin_size):
    result = []
    for i in range(bin_size):
        result.append([value for index, value in enumerate(message) if index % bin_size == i])
    return result


def calculate_bit_difference_byte(byte_1, byte_2):
    '''Calculate the number of bits differing between two bytes.'''
    distance = 0

    # Iterate through each bit
    for i in range(8):
        bitmask = 1 << i

        # Check if bit at bitmask location is different between the two
        if (byte_1 & bitmask) ^ (byte_2 & bitmask):
            distance += 1

    return distance


def calculate_hamming_distance(message1, message2):
    '''Calculate the Hamming distance between two byte arrays.'''
    assert len(message1) == len(message2)

    return sum(calculate_bit_difference_byte(i, k) for i, k in zip(message1, message2))


def guess_keysizes(message):
    '''Return top 5 keysize candidates.'''
    Result = namedtuple('Result', ['distance', 'keysize'])  # pylint: disable=invalid-name
    max_keysize = 40
    result = []
    for keysize in range(1, max_keysize + 1):
        chunks = chunk(message, keysize)

        distance = 0
        for index, i in enumerate(chunks[:-2]):
            distance += calculate_hamming_distance(i, chunks[index+1])

        normalized_diff_occurence = (distance / (len(chunks) - 1)) / keysize
        result.append(Result(normalized_diff_occurence, keysize))

    return [i.keysize for i in sorted(result, key=operator.attrgetter('distance'))[:5]]


def solve_for_key(key_size, message):
    bins = bucket(message, key_size)

    key = []
    for i in bins:
        _, _, bitkey = max(brute_force_byte_key(i))
        key.append(bitkey)

    return bytes(key)


def main():
    with open(os.path.join(os.path.dirname(__file__), 'challenge6_data')) as data_set:
        input_text = ''.join(data_set.read().split())
    binary = codecs.decode(input_text.encode('utf8'), 'base64')

    keysize = guess_keysizes(binary)[0]
    key = solve_for_key(keysize, binary)

    decrypted = decrypt_rotating_bytekey(binary, key)
    assert key.decode() == 'Terminator X: Bring the noise'
    assert decrypted.decode().startswith("I'm back and I'm ringin' the bell")


if __name__ == '__main__':
    main()
