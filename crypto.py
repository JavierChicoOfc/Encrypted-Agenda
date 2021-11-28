import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from typing import Text


class Cryptograpy:
    """
    Class that represents the cryptography methods used in this proyect
    """

    def __init__(self):
      
        self.a_serialize_pw = b'aPW!'

    def hash(self, msg):
        """
        Hashes a given message
        """
        return hashlib.sha256(msg).hexdigest()


    def hash_scrypt(self, text, salt):
        """
        Hash a given text with a salt (Used to hash usernames and passwords)
        """
        kdf = Scrypt(salt=bytes( salt, 'latin-1'),
                     length=32,
                     n=2**14,
                     r=8,
                     p=1)

        return kdf.derive(bytes(text,"latin-1"))

    def pbkdf2hmac(self, key_to_derive, salt_pbk):
        """
        Takes a key and returns a derivation to use it in symmetric cipher
        """
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=16, salt=salt_pbk, iterations=100000)

        return kdf.derive(bytes(key_to_derive, "latin-1"))

    def verify_pbkdf2hmac(self, text, hash, salt_pbk):
        """
        Verifies if the hash is the result of hashing the text, left for future uses
        """
        kdf = PBKDF2HMAC(algorithms=hashes.SHA512(), length=16, salt=salt_pbk, iterations=100000)

        return kdf.verify(bytes(text, "latin-1"), hash)

    def symetric_cipher(self, key, text, iv):
        """
        Use the generated symetric key to cipher a given text (Used to cipher the data in the database)
        """
        # We select CTR as operational mode to cipher blocks due its security and because it is tolerant to losses in blocks
        # (i.e., an error in one block will not affect the rest)
        self.cipher = Cipher(algorithms.AES(key), modes.CTR(iv))

        encryptor = self.cipher.encryptor()
        text = str(text)
        return encryptor.update(bytes(text, "latin-1")) + encryptor.finalize()

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
        Authenticate a given text with an auth_tag (signature)
        """
        h = hmac.HMAC(key,hashes.SHA512())
        h.update(text)

        return h.verify(signature)

    def create_rsa_private_key(self):
        """
        Creates a RSA private key
        """
        return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        )

    def serialize_key(self,certificate):
        """
        Serialize a given key to include it in a file
        """
        return certificate.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.BestAvailableEncryption(self.a_serialize_pw)
                            )

    def signing(self,private_key,message):
        
        return private_key.sign(message,
                            padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                            salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA512()
                            )

    def load_private_key(self,path):
        """
        Deserialize a given private_key
        """
        with open(path, "rb") as key_file:
            pk = serialization.load_pem_private_key(
                                            key_file.read(),
                                            password=self.a_serialize_pw,
                                            )
        return pk

    def load_certificate(self, pem_data):
        """
        Deserialize a given certificate from pem encoded data
        """
        return x509.load_pem_x509_certificate(pem_data)
        
    def verify_sign(self, cert_to_check):
        issuer_public_key = cert_to_check.public_key()
        issuer_public_key.verify(
                            cert_to_check.signature,
                            cert_to_check.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            cert_to_check.signature_hash_algorithm,
                            )


    
        

    
