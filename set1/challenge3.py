# Given the hex string: 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# find the key, which has been XOR to every byte
# Also, what is the message
import codecs

from util import brute_force_byte_key


def main():
    input_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    hex_value = codecs.decode(input_string, 'hex')
    decrypted_candidates = brute_force_byte_key(hex_value)

    _, decrypted_message, key = max(decrypted_candidates)
    assert decrypted_message.decode() == "Cooking MC's like a pound of bacon"
    assert key == 88


if __name__ == '__main__':
    main()
