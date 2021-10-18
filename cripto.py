import os
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#from cryptography.hazmat.backends.interfaces import ScryptBackend

class Criptograpy:
    """
    Class that represents the criptography methods used in this proyect
    """
    def __init__(self):
        
        self.salt_hash = os.urandom(16)

        self.salt_pbkdf2hmac = os.urandom(16)

        self.iv = os.urandom(16)


    def hash(self, text):
        """
        Hash a given text
        """
        kdf = Scrypt(salt=self.salt_hash, length=32, n=2**14, r=8, p=1)#, backend=ScryptBackend)

        return kdf.derive(bytes(text,"latin-1"))

    def verify_hash(self, text, hash):
        """
        Verifies if the hash is the result of hashing the text
        """
        kdf = Scrypt(salt=self.salt_hash, length=32, n=2**14, r=8, p=1)

        return kdf.verify(bytes(text, "latin-1"), hash)

    def pbkdf2hmac(self, text):
        """
        Derives a given text to obtain a key to use un symetric cypher
        """
        kdf = PBKDF2HMAC(algorithms=hashes.SHA512(), length=64, salt=self.salt_pbkdf2hmac, iterations=100000)

        return kdf.derive(bytes(text, "latin-1"))

    def pbkdf2hmac(self, text, hash):
        """
        Verifies if the hash is the result of hashing the text
        """
        kdf = PBKDF2HMAC(algorithms=hashes.SHA512(), length=64, salt=self.salt_pbkdf2hmac, iterations=100000)

        return kdf.verify(bytes(text, "latin-1"), hash)

    def hmac(self):

        pass

    def symetric_cipher(self, key, text):
        """
        Use the generated symetric key to cipher a given text
        """
        self.cipher = Cipher(algorithms.AES(key), modes.CTR(self.iv))

        encryptor = self.cipher.encryptor()

        return encryptor.update(bytes(text,"latin-1")) + encryptor.finalize()

    def symetric_decrypter(self, text):
        """
        Use the genrated symetric key to decrypt a given text
        """
        decryptor = self.cipher.decryptor()

        return decryptor.update(text) + decryptor.finalize()


    
        

    
