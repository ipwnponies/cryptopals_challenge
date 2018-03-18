import codecs

input_text = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
key = 'ICE'
expected_output = '''0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'''


if __name__ == '__main__':
    def xor(index, char):
        # Use modulo to apply rotating byte key
        byte_key = index % len(key)

        return ord(char) ^ ord(key[byte_key])

    encrypted_bytes = bytes(xor(index, byte) for index, byte in enumerate(input_text))
    # Use codecs.decode to convert a hex string into plain hex bytes
    assert str(codecs.encode(encrypted_bytes, 'hex'), 'utf8') == expected_output
