from util import chunk


def pkcs_padding(message, chunk_size):
    '''Pad the message at the end with \x04 characters to get even block sizes.'''
    chunked = chunk(message, chunk_size)
    chunked[-1] = '{message:\x04<{chunk_size}}'.format(message=chunked[-1], chunk_size=chunk_size)
    return ''.join(chunked)


def main():
    assert pkcs_padding('YELLOW SUBMARINE', 20) == 'YELLOW SUBMARINE\x04\x04\x04\x04'


if __name__ == '__main__':
    main()
