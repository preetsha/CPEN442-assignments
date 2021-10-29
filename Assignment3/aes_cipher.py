from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

class AESCipher(object):
    def __init__(self, key):
        AES_key = key
        if isinstance(key, str):
            AES_key = AES_key.encode()
        else:
            AES_key = AES_key % 65536
            AES_key = AES_key.to_bytes(16, 'big')

        print(AES_key)
        self.cipher = AES.new(AES_key, AES.MODE_ECB)
            

    def encrypt(self, plaintext):
        ciphertext = self.cipher.encrypt(pad(plaintext.encode(), 16))
        return base64.b64encode(ciphertext).decode()

    def decrypt(self, ciphertext):
        ciphertext_bytes = base64.b64decode(ciphertext)
        plaintext = unpad(self.cipher.decrypt(ciphertext_bytes), 16)
        return plaintext.decode('utf-8')