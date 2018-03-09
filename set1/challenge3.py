# Given the hex string: 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# find the key, which has been XOR to every byte
# Also, what is the message
import codecs

input_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
hex_value = codecs.decode(input_string, 'hex')


def score_english(message):
    common_letters = 'ETAOIN SHRDLU'
    score = sum(1 for i in message if chr(i).upper() in common_letters)
    return score

results = []
# Byte key size range is 256 possible keys
for key in range(256):
    candidate = bytes([i ^ key for i in hex_value])
    results.append((score_english(candidate), candidate))

print(str(max(results)[1], 'utf8'))
