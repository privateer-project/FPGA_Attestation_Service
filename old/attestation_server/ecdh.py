# ECDH Encrypted Key Exchange
# https://gist.github.com/byt3bl33d3r/84e298c62b310509febf8a4a90f82893
# Modified by: Ilias Papalamprou

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from secrets import token_bytes

# Added
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class DiffieHellman:
    def __init__(self):
        self.diffieHellman = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.diffieHellman.public_key()
        # self.IV = token_bytes(16)
        # TODO : Better is to have random generation each time
        self.IV = b'T\x19F\xbdy2\x0f\x918\x80\xa5\x1a\xe4\xf39\x06'

    def encrypt(self, public_key, secret):
        shared_key = self.diffieHellman.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(self.IV), backend=default_backend())
        encryptor = aes.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(secret.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, public_key, secret, iv):
        shared_key = self.diffieHellman.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        decryptor = aes.decryptor()
        decrypted_data = decryptor.update(secret) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()


# Added functions
def get_key_hex(public_key_object):
    public_key_bytes = public_key_object.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_hex = public_key_bytes.hex()
    return public_key_hex

def get_key_object(public_key_received_bytes):
    received_public_key = serialization.load_der_public_key(
        public_key_received_bytes,
        backend=default_backend()
    )
    return received_public_key
