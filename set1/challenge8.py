import codecs
import os


def chunk(message, chunk_size):
    result = []
    for index in range(0, len(message), chunk_size):
        result.append(message[index:index + chunk_size])
    return result


def main():
    with open(os.path.join(os.path.dirname(__file__), 'challenge8_data')) as data_set:
        input_text = [codecs.decode(i.encode('utf8'), 'base64') for i in data_set.readlines()]

    linenumber_ecb_encrypted = []
    for line_number, cipher_text in enumerate(input_text):
        chunks = chunk(cipher_text, 16)
        if len(chunks) != len(set(chunks)):
            linenumber_ecb_encrypted.append(line_number)

    assert linenumber_ecb_encrypted == [132]


if __name__ == '__main__':
    main()
