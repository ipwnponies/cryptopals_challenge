# Given the hex string: 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# find the key, which has been XOR to every byte
# Also, what is the message
import codecs


def score_english(message):
    common_letters = 'ETAOIN SHRDLU'
    score = sum(1 for i in message if chr(i).upper() in common_letters)
    return score


def brute_force_byte_key(message):
    results = []
    # Byte key size range is 256 possible keys
    for key in range(256):
        candidate = bytes([i ^ key for i in message])
        results.append((score_english(candidate), candidate, key))
    return results


if __name__ == '__main__':
    input_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    hex_value = codecs.decode(input_string, 'hex')
    decrypted_candidates = brute_force_byte_key(hex_value)

    _, decrypted_message, key = max(decrypted_candidates)
    print(str(decrypted_message, 'utf8'))
    print('Key is {}.'.format(key))
