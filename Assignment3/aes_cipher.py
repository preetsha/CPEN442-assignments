# TODO implement the actual AES Cipher
# NOTE: Right now this is a placeholder module. "Encryption" just adds the key to the front
#       and "decryption" removes that key from the front
class AESCipher(object):
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        ciphertext = str(self.key) + plaintext
        return ciphertext

    def decrypt(self, ciphertext):
        
        # print(f"Decrypting: {ciphertext}")
        plaintext = ciphertext[len(str(self.key)):len(ciphertext)]
        # print(f"Result    : {plaintext}")
        return plaintext