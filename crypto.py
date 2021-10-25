from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes,hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Cryptograpy:
    """
    Class that represents the cryptography methods used in this proyect
    """
    def __init__(self):
        """
        Constructor class that have salts and iv for the differents algorithms
        """

        #self.salt_hash = b'1Q\xc7k\xf9\x9dl\x89\xc43\xba\x1fB\xaa\x1'

        self.salt_pbkdf2hmac = b'\x82\x167\x18\xf2\xc9\x80-~@\xf3\xe5\x1e.\x8d\x95'
        
        #self.iv = b'\xd6Gqb\xc9X\xd1\x85f\xfb\x03\xa3\xe4v\x10e'

        #self.key_hmac = b'&Nv\xf3kh\x82\x12l\x88\xaf\xfc\xe4\xaem}'


    def hash_scrypt(self, text, salt):
        """
        Hash a given text (Used to hash usernames and passwords)
        """
        kdf = Scrypt(salt=bytes( salt, 'latin-1'),
                     length=32,
                     n=2**14,
                     r=8,
                     p=1)

        return kdf.derive(bytes(text,"latin-1"))

    def pbkdf2hmac(self, key_to_derive):
        """
        Takes a key returns a derivation to use it in symmetric cipher
        """
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=16, salt=self.salt_pbkdf2hmac, iterations=100000)

        return kdf.derive(bytes(key_to_derive, "latin-1"))

    def verify_pbkdf2hmac(self, text, hash):
        """
        Verifies if the hash is the result of hashing the text
        """
        kdf = PBKDF2HMAC(algorithms=hashes.SHA512(),
                         length=64,
                         salt=self.salt_pbkdf2hmac,
                         iterations=100000)

        return kdf.verify(bytes(text, "latin-1"), hash)

    def symetric_cipher(self, key, text, iv):
        """
        Use the generated symetric key to cipher a given text (Used to cipher the data in the database)
        """
        self.cipher = Cipher(algorithms.AES(key), modes.CTR(iv))

        encryptor = self.cipher.encryptor()
        text = str(text)
        return encryptor.update( bytes( text, "latin-1" ) ) + encryptor.finalize()

    def symetric_decrypter(self, key, text, iv):
        """
        Use the genrated symetric key to decrypt a given text
        """
        self.cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        decryptor = self.cipher.decryptor()

        return decryptor.update(text) + decryptor.finalize()

    def hmac(self, key, text):
        """
        Authenticate a given text with an auth_tag (h.finalize())
        """
        h = hmac.HMAC(key,hashes.SHA512())
        h.update(text)

        return h.finalize()

    def verify_hmac(self,key,text,signature):
        """
        Authenticate a given text with an auth_tag (h.finalize())
        """
        h = hmac.HMAC(key,hashes.SHA512())
        h.update(text)

        return h.verify(signature)



    
        

    
