from Crypto.Cipher import AES

from util import chunk
from util import detect_block_size
from util import generate_random_bytes
from util import pkcs_padding


def decode_cookie(encoded_cookie):
    entries = encoded_cookie.split('&')
    result = {}
    for i in entries:
        key, _, value = i.partition('=')
        if not key:
            raise Exception('Not a key value pair: {}'.format(i))
        result[key] = value

    return result


def encode_cookie(cookie):
    result = [
        '{}={}'.format(key, value)
        for key, value in cookie.items()
    ]
    return '&'.join(result)


def profile_for(email):
    # Sanitize input, not meta characters allowed
    email = email.replace('&', '').replace('=', '')

    # Role is hardcoded to user because this is supposed to be "secure" and not allow for generating admin user role
    user_profile = {
        'email': email,
        'uid': 10,
        'role': 'user',
    }

    return encode_cookie(user_profile)


def encrypt_profile(profile, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pkcs_padding(profile.encode(), 16)
    return cipher.encrypt(padded_plaintext)


def decrypt_profile(key, profile):
    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = cipher.decrypt(profile).decode()

    # Santize input by stripping out any padding characters
    return plaintext.rstrip('\x04')


def _assert_block_size():
    '''Detect and assert that encryption is AES in ECB mode.'''

    # AES keys can be 16, 24, or 32 bytes.
    # This doesn't affect the block size, which is fixed at 16 bytes.
    key_size = 32
    block_size = 16

    key = generate_random_bytes(key_size)

    # Pad out user input with 3 times blocksize
    # This will guarantee a minimum of at 2 complete blocks of identical data
    user_input = '\x00' * block_size * 3
    message = oracle(user_input, key)

    chunks = chunk(message, block_size)
    assert len(chunks) != len(set(chunks)), 'There should be duplicate blocks using ECB.'

    detected_size = detect_block_size(key, oracle)
    assert detected_size == block_size, (
        'This is supposed to be AES encrypted, 16 byte block sizes. '
        f'Detected block size of {detected_size} instead.'
    )


def oracle(user_input, key):
    profile = profile_for(user_input)
    return encrypt_profile(profile, key)


def main():
    key = generate_random_bytes(16)

    profile1 = profile_for('foo@bar.commm')
    encrypted_profile1 = encrypt_profile(profile1, key)

    _assert_block_size()

    decrypted = decode_cookie(decrypt_profile(key, encrypted_profile1))
    assert decrypted['email'] == 'foo@bar.commm'
    assert decrypted['role'] == 'user'


if __name__ == '__main__':
    main()
