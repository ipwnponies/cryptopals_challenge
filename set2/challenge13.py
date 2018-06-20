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


def get_user_profile_username(key):
    '''Set up the profile (with user) to be patched.

    Manipulate input to align 'role=' at block boundary. Blocks from the second profile will be takenk to follow up and
    set the value to admin.
    '''
    # block 1           block 2             block3
    # email=foo@bar     .com&uid=10&role=   user...

    # Calculate how many bytes of input required to align the role input into separate block.
    # This is multple of AES blocksize, 16 bytes.
    num_chars_padding = 16 - len('email=' + '&uid=10&role=') % 16

    username = 'a' * num_chars_padding

    profile1 = profile_for(username)
    return encrypt_profile(profile1, key), username


def get_user_profile_with_admin(key):
    '''Get a user profile with exploit payload setup.

    Manipulate the input to get 'admin' from input to be at the start of block boundary. Insert padding at the end to
    make it look last AES block (padding).
    '''
    # Padding character is determined by inspecting the oracle function, which is freely available to attacker.
    # They can inspect the open source to understand the padding scheme and how to use it to exploit ECB.
    padding = '\x04'

    desired_role = 'admin'
    num_padding = 16 - len(desired_role)
    exploit_payload = desired_role + padding * num_padding
    assert len(exploit_payload) == 16, (
        'The admin value payload needs to fill out its own AES block entirely (16 bytes). '
        'This allows for patching into another payload without corrupting the data structure. '
    )

    # block 1           block 2                 block3
    # email=aaaaaaaaaa  admin\x04\x04...        &uid=10&role=user...
    prefix_length = 16 - len('email=')

    unused_email_prefix = 'a' * prefix_length
    profile2 = profile_for(unused_email_prefix + exploit_payload)
    return encrypt_profile(profile2, key)


def main():
    key = generate_random_bytes(16)

    _assert_block_size()

    encrypted_profile1, username = get_user_profile_username(key)
    decrypted_profile1 = decode_cookie(decrypt_profile(key, encrypted_profile1))
    assert decrypted_profile1['email'] == username == 'aaaaaaaaaaaaa', (
        'Email should be 13 characters, that is required length to setup first profile.'
    )

    encrypted_profile2 = get_user_profile_with_admin(key)
    decrypted_profile2 = decode_cookie(decrypt_profile(key, encrypted_profile2))
    assert decrypted_profile2['email'][-16:] == ('admin' + '\x04' * 11), (
        'Last 16 bytes of input should be dedicated to payload and look like last AES block.'
    )


if __name__ == '__main__':
    main()
