from Crypto.Cipher import AES

from util import generate_random_bytes
from util import pkcs_padding


def decode_cookie(encoded_cookie):
    # Santize input by stripping out any padding characters
    encoded_cookie = encoded_cookie.rstrip('\x04')

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


def main():
    profile = profile_for('foo@bar.com')

    key = generate_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)

    encrypted_profile = cipher.encrypt(pkcs_padding(profile.encode(), 16))

    decrypted = decode_cookie(cipher.decrypt(encrypted_profile).decode())
    assert decrypted['email'] == 'foo@bar.com'
    assert decrypted['role'] == 'user'


if __name__ == '__main__':
    main()
