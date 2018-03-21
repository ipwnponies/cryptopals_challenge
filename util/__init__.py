def brute_force_byte_key(message):
    results = []
    # Byte key size range is 256 possible keys
    for key in range(256):
        candidate = bytes([i ^ key for i in message])
        results.append((_score_english(candidate), candidate, key))
    return results


def decrypt_rotating_bytekey(message, key):
    binary_key = key.encode('utf8')

    # Use modulo to circularly get applicable byte from key
    return bytes(char ^ binary_key[index % len(binary_key)] for index, char in enumerate(message.encode()))


def _score_english(message):
    '''Calculate naive score for presence of common English letters.

    This uses a naive heuristic to score a message. It assigns an unweighted value when a common
    English letter is detected.
    '''
    common_letters = 'ETAOIN SHRDLU'
    return sum(1 for i in message if chr(i).upper() in common_letters)
