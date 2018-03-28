import codecs
import os

from util import decrypt_rotating_bytekey
from util import decrypt_ecb

KEY = 'YELLOW SUBMARINE'


def main():
    with open(os.path.join(os.path.dirname(__file__), 'challenge7_data')) as data_set:
        input_text = data_set.read()
    message = codecs.decode(input_text.encode('utf8'), 'base64')
    decrypted = decrypt_ecb(message, KEY)

    assert decrypted.decode().startswith("I'm back and I'm ringin' the bell")


if __name__ == '__main__':
    main()
