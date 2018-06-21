from Crypto.Cipher import AES

from util import chunk
from util import detect_block_size
from util import generate_random_bytes
from util import pkcs_padding


class Oracle():
    def __init__(self):
        self.key = generate_random_bytes(16)

    def get_user_profile(self, email):
        return self.encrypt_profile(self.profile_for(email))

    def encrypt_profile(self, profile):
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_plaintext = pkcs_padding(profile.encode(), 16)
        return cipher.encrypt(padded_plaintext)

    def decrypt_profile(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_ECB)

        plaintext = cipher.decrypt(ciphertext).decode()

        # Santize input by stripping out any padding characters
        return plaintext.rstrip('\x04')

    @staticmethod
    def profile_for(email):
        # Sanitize input, not meta characters allowed
        email = email.replace('&', '').replace('=', '')

        # Role is hardcoded to user because this is supposed to be "secure" and not allow for generating admin user role
        user_profile = {
            'email': email,
            'uid': 10,
            'role': 'user',
        }

        return Oracle.encode_cookie(user_profile)

    @staticmethod
    def decode_cookie(encoded_cookie):
        entries = encoded_cookie.split('&')
        result = {}
        for i in entries:
            key, _, value = i.partition('=')
            if not key:
                raise Exception('Not a key value pair: {}'.format(i))
            result[key] = value

        return result

    @staticmethod
    def encode_cookie(cookie):
        result = [
            '{}={}'.format(key, value)
            for key, value in cookie.items()
        ]
        return '&'.join(result)


def _assert_block_size(oracle):
    '''Detect and assert that encryption is AES in ECB mode.'''

    # AES keys can be 16, 24, or 32 bytes.
    # This doesn't affect the block size, which is fixed at 16 bytes.
    key_size = 32
    block_size = 16

    key = generate_random_bytes(key_size)

    # Pad out user input with 3 times blocksize
    # This will guarantee a minimum of at 2 complete blocks of identical data
    user_input = '\x00' * block_size * 3
    message = oracle.encrypt_profile(Oracle.profile_for(user_input))

    chunks = chunk(message, block_size)
    assert len(chunks) != len(set(chunks)), 'There should be duplicate blocks using ECB.'

    detected_size = detect_block_size(key, lambda x, y: oracle.encrypt_profile(Oracle.profile_for(x)))

    assert detected_size == block_size, (
        'This is supposed to be AES encrypted, 16 byte block sizes. '
        f'Detected block size of {detected_size} instead.'
    )


def get_user_profile_username():
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

    return username


def get_user_profile_with_admin():
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
    return unused_email_prefix + exploit_payload


def detect_exploit_start_boundary():
    '''Get the first byte where inserted exploit can be found.

    Block1              Block2              Block3
    email=aaaaaaaaaa    admin-----------    &uid=10&role=user
                        ^
    '''
    # Number of blocks before input with exploit. This value is determined from analysis of the k-v encoding source to
    # see how much overhead exists before user input.
    return (len('email=') // 16 + 1) * 16


def detect_profile_end_boundary():
    '''Get the first byte where exploit should be inserted.

    Block1              Block2              Block3              Block4
    email=aaaaaaaaaa    aaa&uid=10&role=    user
                                            ^
    '''
    # Number of blocks (in bytes) remaining, after segmenting role.  This value is determined from analysis of the
    # encoded cookie source.
    return (len('user') // 16 + 1) * 16


def main():
    oracle = Oracle()

    _assert_block_size(oracle)

    username1 = get_user_profile_username()
    encrypted_profile1 = oracle.get_user_profile(username1)
    decrypted_profile1 = Oracle.decode_cookie(oracle.decrypt_profile(encrypted_profile1))
    assert decrypted_profile1['email'] == username1 == 'aaaaaaaaaaaaa', (
        'Email should be 13 characters, that is required length to setup first profile.'
    )

    username2 = get_user_profile_with_admin()
    encrypted_profile2 = oracle.get_user_profile(username2)
    decrypted_profile2 = Oracle.decode_cookie(oracle.decrypt_profile(encrypted_profile2))
    assert decrypted_profile2['email'][-16:] == ('admin' + '\x04' * 11), (
        'Last 16 bytes of input should be dedicated to payload and look like last AES block.'
    )

    # Insert the exploit block to the first profile. The exploit block is setup to look like the last block.
    # block 1           block 2             block3
    # email=foo@bar     .com&uid=10&role=   user...
    # email=aaaaaaaaaa  admin\x04\x04...    &uid=10&role=user...
    assert encrypted_profile1[:16] == encrypted_profile2[:16], (
        'The first block should be identical since both profiles start with teh same email prefix.'
    )
    assert encrypted_profile1[16:32] != encrypted_profile2[16:32], (
        'The second block should differ: '
        'Profile1 has the role param left aligned. '
        'Profile2 has the role value left aligned. '
        'If the second blocks are the same, that means the input email is unnecessarily long. Just shift the splice '
        'point further along for both profiles.'
    )

    right_boundary = detect_profile_end_boundary()
    exploit_start_boundary = detect_exploit_start_boundary()
    admin_encrypted_profile = encrypted_profile1[0:-right_boundary] + \
        encrypted_profile2[exploit_start_boundary:exploit_start_boundary + 16]

    admin_profile = Oracle.decode_cookie(oracle.decrypt_profile(admin_encrypted_profile))
    assert admin_profile['email'] == username1, 'Email should come from first profile'
    assert admin_profile['role'] == 'admin', (
        'role is {} but should come from second profile'.format(admin_profile['role'])
    )


if __name__ == '__main__':
    main()
