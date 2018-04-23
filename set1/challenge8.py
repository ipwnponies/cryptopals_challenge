import codecs
import os

from util import detect_ecb


def main():
    with open(os.path.join(os.path.dirname(__file__), 'challenge8_data')) as data_set:
        input_text = [codecs.decode(i.encode('utf8'), 'base64') for i in data_set.readlines()]

    linenumber_ecb_encrypted = []
    for line_number, cipher_text in enumerate(input_text):
        if detect_ecb(cipher_text):
            linenumber_ecb_encrypted.append(line_number)

    assert linenumber_ecb_encrypted == [132]


if __name__ == '__main__':
    main()
