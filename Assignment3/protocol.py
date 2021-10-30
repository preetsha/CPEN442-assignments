import secrets
import hashlib

from aes_cipher import AESCipher
class Protocol:
    # Initializer (Called from app.py)
    def __init__(self, shared_secret):
        self._key = None

        # Set the secret
        self.shared_secret = shared_secret.get()
        
        # If shared secret is too long, cut it down to 16 chars (128 bits) for AES
        if len(self.shared_secret) > 16:
            self.shared_secret = self.shared_secret[0:16]
        
        # If shared secret is too short, pad it to 16 chars
        while len(self.shared_secret) < 16:
            self.shared_secret = self.shared_secret + "0" # TODO: confirm whether to pre-pad or post-pad

        # Compute g^x mod p, which we'll call the "Generated Value"
        # Diffie-Hellmann public constants
        self.p = int("0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF", 16)
        self.g = 2  # Computationally efficient https://eli.thegreenplace.net/2019/diffie-hellman-key-exchange/
        
        # Diffie-Hellman private generated values
        self.secret_exponent = secrets.randbelow(self.p-4) + 2
        self.generated_value = pow(self.g, self.secret_exponent, self.p)
        
        # Generate a nonce challenge
        self.nonce = secrets.randbelow(self.p-4) + 2

        # Assign identity (later) to maintain message directionality
        # Note: This is to prevent replay attacks
        self.identity = None
        pass

    def AbortConnection(self, error_msg):
        self.shared_secret = None
        self.secret_exponent = None
        self.identity = None
        self._key = None
        raise ConnectionAbortedError(f"{error_msg}")

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    def GetProtocolInitiationMessage(self):
        # This instance is initiating the secure connection,
        self.identity = "ALICE"

        # Encrypt g^a mod p
        sensitive_data = str(self.generated_value)
        encrypted_payload = AESCipher(self.shared_secret).encrypt(sensitive_data)
        
        # Format the message to match our protocol
        # "INIT$Alice$R1$E(g^a modp, Kab)"
        message = ["INIT", self.identity, str(self.nonce), encrypted_payload]
        message = "$".join(message)
        return message


    # Checking if a received message is part of your protocol (called from app.py)
    def IsMessagePartOfProtocol(self, message):
        tokenized_msg = message.decode().split("$", 1) 
        # Check if message starts with the proper protocol tags
        if self.identity == "ALICE":
            return tokenized_msg[0] in ["SQCK"]
        else:
            return tokenized_msg[0] in ["INIT", "ACKK"]

    # Processing protocol message
    def ProcessReceivedProtocolMessage(self, message):        
        # Set this instance as the receiver
        self.identity = "BOB" if self.identity == None else self.identity
        
        # Check first 4 chars for message type
        msg_type = message.decode()[0:4]
        
        if msg_type == "INIT":
            print("Received INIT")
            # Extract message contents
            tokenized_msg = message.decode().split("$", 3) # Only splits on first three $'s
                        
            if len(tokenized_msg) < 4:
                self.AbortConnection("Connection Aborted: Invalid Message Format")
            
            sender = tokenized_msg[1]
            challenge = tokenized_msg[2]
            cipher_text = tokenized_msg[3]

            # Enforce directionality
            if sender == self.identity:
                self.AbortConnection("Connection Aborted: Invalid Sender")

            # Generate a response to the challenge
            challenge_response = challenge
            plain_text = AESCipher().decrypt(self.shared_secret, cipher_text)

            self.SetSessionKey(pow(int(plain_text), self.secret_exponent, self.p))

            # Encrypt our identity, g^b mod p, and h(R1)
            sensitive_data = f"{self.identity}${str(self.generated_value)}${challenge_response}"
            encrypted_payload = AESCipher(self.shared_secret).encrypt(sensitive_data)

            # Format the message to match our protocol
            # R2$E("Bob", g^b mod p, h(R1), Kab)
            response = ["SQCK", str(self.nonce), encrypted_payload]
            response = "$".join(response)

            return response

        elif msg_type == "SQCK":
            print("Received SQCK")
            # Extract message contents
            tokenized_msg = message.decode().split("$", 2) # Only splits on first two $'s #TODO: check size of tokenized msg
            
            if len(tokenized_msg) < 2:
                self.AbortConnection("Connection Aborted: Invalid Plaintext Format")
            
            challenge = tokenized_msg[1]
            cipher_text = tokenized_msg[2]

            # Extract plaintext contents
            plain_text = AESCipher().decrypt(self.shared_secret, cipher_text)
            tokenized_plain_text = plain_text.split("$", 2)  #TODO: check size of tokenized plain text
            
            if len(tokenized_plain_text) < 3:
                self.AbortConnection("Connection Aborted: Invalid Plaintext Format")
            
            sender = tokenized_plain_text[0]
            sender_exponent = tokenized_plain_text[1]
            sender_solution = tokenized_plain_text[2]

            # Enforce directionality"
            if sender != "BOB":
                self.AbortConnection("Connection Aborted: Invalid Sender")

            # Check that challenge was satisfied
            if int(sender_solution) != self.nonce:
                self.AbortConnection("Connection Aborted: Received Wrong Challenge Response")

            # maybe sender exponent should be like sender_generated_value since they
            # send g^a mod p/g^b mod p and not just a/b
            self.SetSessionKey(pow(int(sender_exponent), self.secret_exponent, self.p))

            # Generate a response to the challenge
            challenge_response = challenge
            
            # Encrypt our identity and h(R2)
            sensitive_data = f"{self.identity}${challenge_response}"
            encrypted_payload = AESCipher(self.shared_secret).encrypt(sensitive_data)
            
            # Format the message to match our protocol
            # E("ALICE", h(R2), Kab)
            response = f"ACKK${encrypted_payload}"
            return response

        elif msg_type == "ACKK":
            print("Received ACKK")
            tokenized_msg = message.decode().split("$", 1) # Only splits on the first $
            cipher_text = tokenized_msg[1]
            
            # Extract plaintext contents
            plain_text = AESCipher().decrypt(self.shared_secret, cipher_text)
            tokenized_plain_text = plain_text.split("$", 1)
            sender = tokenized_plain_text[0]
            sender_solution = tokenized_plain_text[1]

            # Enforce directionality
            if sender != "ALICE":
                self.AbortConnection("Connection Aborted: Invalid Sender")

            # Check that challenge was satisfied
            if int(sender_solution) != self.nonce:
                self.AbortConnection("Connection Aborted: Received Wrong Challenge Response")
            
            print("Connection Secured")

            return ""

        else:
            self.AbortConnection("Connection Aborted: Received Unknown Protocol Message")

    # Setting the key for the current session
    def SetSessionKey(self, key):
        self._key = key
        pass

    # Helper function for encapsulation
    def GetSessionKey(self):
        return self._key

    # Encrypting messages
    def EncryptAndProtectMessage(self, plain_text):
        # Encrypt with the session key if both parties have it
        if self.GetSessionKey():
            plain_text_hash = hashlib.sha256(plain_text.encode()).hexdigest()
            message = f"{plain_text}${plain_text_hash}"
            cipher_text = AESCipher(self.GetSessionKey()).encrypt(message)
            
            print(f"Encrypting: {message}")
            print(f"Sending   : {cipher_text}\n")
            return cipher_text
        
        # Otherwise, don't perform encryption since the connection hasn't
        # been secured yet
        return plain_text


    # Decrypting and verifying messages
    def DecryptAndVerifyMessage(self, cipher_text):
        # Decrypt the message if a session key has been established
        if self.GetSessionKey():
            message = AESCipher().decrypt(self.GetSessionKey(), cipher_text.decode())
            
            # Extract message contents
            tokenized_message = message.split("$", 1)
            if len(tokenized_message) < 2:
                return cipher_text # The integrity check hash is missing
                
            plain_text = tokenized_message[0]
            plain_text_hash = tokenized_message[1]

            print(f"Received    : {cipher_text.decode()}")
            print(f"Decrypted to: {message}")
            # Perform integrity check by comparing hash of plaintext to
            # the hash supplied in the message
            if plain_text_hash == hashlib.sha256(plain_text.encode()).hexdigest():
                print(f"PASSED INTEGRITY CHECK!\n")
                return plain_text.encode()
            else:
                self.AbortConnection("Connection Aborted: Message Integrity Violated")

        # Otherwise, the connection hasn't been secured yet, so don't decrypt
        return cipher_text
