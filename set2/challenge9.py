from util import chunk


def pkcs_padding(message, chunk_size):
    '''Pad the message at the end with \x04 characters to get even block sizes.'''
    chunked = chunk(message, chunk_size)
    chunked[-1] = chunked[-1].ljust(chunk_size, b'\x04')
    return b''.join(chunked)


def main():
    assert pkcs_padding(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'


if __name__ == '__main__':
    main()
