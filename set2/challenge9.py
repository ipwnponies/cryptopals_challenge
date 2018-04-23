from util import pkcs_padding


def main():
    assert pkcs_padding(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'


if __name__ == '__main__':
    main()
