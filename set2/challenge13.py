from Crypto.Cipher import AES

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


def encrypt_profile(key, profile):
    cipher = AES.new(key, AES.MODE_ECB)

    return cipher.encrypt(pkcs_padding(profile.encode(), 16))


def decrypt_profile(key, profile):
    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = cipher.decrypt(profile).decode()

    # Santize input by stripping out any padding characters
    return plaintext.rstrip('\x04')


def main():
    key = generate_random_bytes(16)

    profile1 = profile_for('foo@bar.commm')
    encrypted_profile1 = encrypt_profile(key, profile1)

    decrypted = decode_cookie(decrypt_profile(key, encrypted_profile1))
    assert decrypted['email'] == 'foo@bar.commm'
    assert decrypted['role'] == 'user'


if __name__ == '__main__':
    main()
