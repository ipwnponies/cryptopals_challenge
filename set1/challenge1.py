import codecs


def main():
    input_string = (
        '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f'
        '69736f6e6f7573206d757368726f6f6d'
    )
    hex_value = codecs.decode(input_string, 'hex')
    base64_value = codecs.encode(hex_value, 'base64')

    assert base64_value.decode('utf-8').strip() == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'


if __name__ == '__main__':
    main()
