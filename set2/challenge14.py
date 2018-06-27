from set2.challenge13 import Oracle


class HarderOracle(Oracle):
    def __init__(self):
        super().__init__()
        self.prefix = 'sdfdafsasa'

    def encrypt_profile(self, profile):
        # Inject random prefix
        return super().encrypt_profile(self.prefix + profile)

    def decrypt_profile(self, ciphertext):
        plaintext = super().decrypt_profile(ciphertext)
        assert plaintext.startswith(self.prefix)

        # Strip random prefix
        return plaintext[len(self.prefix):]


def main():
    oracle = HarderOracle()
    profile_encrypted = oracle.get_user_profile('test')
    profile_plain = Oracle.decode_cookie(oracle.decrypt_profile(profile_encrypted))
    assert profile_plain['email'] == 'test'


if __name__ == '__main__':
    main()
