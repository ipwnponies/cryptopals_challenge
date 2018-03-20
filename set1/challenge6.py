import codecs
import os.path
import operator
from collections import namedtuple

from challenge3 import brute_force_byte_key
from challenge5 import xor


def chunk(message, chunk_size):
    result = []
    for index in range(0, len(message), chunk_size):
        result.append(message[index:index + chunk_size])
    return result


def bin(message, bin_size):
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
    Result = namedtuple('Result', ['distance', 'keysize'])
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
    bins = bin(message, key_size)

    key = []
    for i in bins:
        _, _, bitkey = max(brute_force_byte_key(i))
        key.append(bitkey)

    return bytes(key)




def main():
    with open(os.path.join(os.path.dirname(__file__), 'challenge6_data')) as f:
        input_text = ''.join(f.read().split())
    binary = codecs.decode(input_text.encode('utf8'), 'base64')

    keysize = guess_keysizes(binary)[0]
    key = solve_for_key(keysize, binary)

    decrypted = bytes(xor(key, index, byte) for index, byte in enumerate(binary))
    print(str(decrypted, 'utf8'))
    print('The key is {}.'.format(str(key, 'utf8')))


if __name__ == '__main__':
    main()