import codecs

input_text = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
KEY = 'ICE'
expected_output = '''0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'''


def xor(key, index, char):
    # Use modulo to apply rotating byte key
    byte_key = index % len(key)

    return char ^ key[byte_key]


def main():
    encrypted_bytes = bytes(xor(KEY.encode(), index, byte) for index, byte in enumerate(input_text.encode()))
    # Use codecs.decode to convert a hex string into plain hex bytes
    assert codecs.encode(encrypted_bytes, 'hex').decode('utf8') == expected_output


if __name__ == '__main__':
    main()
