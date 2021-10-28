from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import ast
# TODO implement the actual AES Cipher
# NOTE: Right now this is a placeholder module. "Encryption" just adds the key to the front
#       and "decryption" removes that key from the front
class AESCipher(object):
    def __init__(self, key):
        self.key = key
        self.cipher = AES.new(key.encode(), AES.MODE_ECB)

    def encrypt(self, plaintext):
        print(f"Encrypting: {plaintext}")
        # while len(plaintext) % 16 != 0:
        #     plaintext += '\x00'
        ciphertext = self.cipher.encrypt(pad(plaintext.encode(), 16))
        print(ciphertext, len(ciphertext))
        return str(ciphertext)

    def decrypt(self, ciphertext):
        print(f"Decrypting: {ciphertext}, Length of Ciphertext: {len(ciphertext)}")
        ciphertext_bytes = ast.literal_eval(ciphertext)
        # while len(ciphertext) % 16 != 0:
        #     ciphertext += '\x00'
        # plaintext = ciphertext[len(str(self.key)):len(ciphertext)]
        plaintext = unpad(self.cipher.decrypt(ciphertext_bytes), 16)
        # print(f"Result    : {plaintext}")
        return plaintext.decode()