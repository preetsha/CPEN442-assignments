from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
import base64

def formatKey(key):
        AES_key = key
        if isinstance(key, str):
            AES_key = AES_key.encode()
        else:
            AES_key = AES_key % pow(2, 128)
            AES_key = AES_key.to_bytes(16, 'big')
        return AES_key

class AESCipher(object):
    def __init__(self, key = None):
        if key:
            AES_key = formatKey(key)
            
            iv = Random.new().read(AES.block_size)
            self.cipher = AES.new(AES_key, AES.MODE_CBC, iv)

    def encrypt(self, plaintext):
        ciphertext = self.cipher.encrypt(pad(plaintext.encode(), 16))
        return base64.b64encode(self.cipher.iv + ciphertext).decode()

    def decrypt(self, key, ciphertext):
        ciphertext_bytes = base64.b64decode(ciphertext)
        iv = ciphertext_bytes[:AES.block_size]
        # Get IV and update cipher
        self.cipher = self.cipher = AES.new(formatKey(key), AES.MODE_CBC, iv)  
        plaintext = unpad(self.cipher.decrypt(ciphertext_bytes[AES.block_size:]), 16)
        return plaintext.decode('utf-8')