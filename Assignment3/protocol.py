import secrets
import hashlib

from aes_cipher import AESCipher
class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        input_secret = "thiskeyyyyistoolong" # TODO Change how we read in this value
        
        # If shared secret is too long, cut it down to 16 chars (128 bits) for AES
        if len(input_secret) > 16:
            input_secret = input_secret[0:16]
        
        # If shared secret is too short, pad it to 16 chars
        while len(input_secret) < 16:
            input_secret = input_secret + "0"

        # Set the secre
        self.shared_secret = input_secret

        # Compute g^x mod p, which we'll call the "Generated Value"
        self.p = 7 # TODO Change later, we need this number to be bigger
        self.g = 3 # TODO Change later (make sure g is a primitive root modulo p)
        self.secret_exponent = secrets.randbelow(10) + 1 # TODO Increase later
        self.generated_value = (self.g ** self.secret_exponent) % self.p
        
        # Generate a nonce challenge
        self.nonce = secrets.randbelow(10) + 1 # TODO Increase range later
        self.hash_of_nonce = hashlib.sha256(str(self.nonce).encode()).hexdigest()

        # Assign identity (later) to maintain message directionality
        # Note: This is to prevent replay attacks
        self.identity = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        # This instance is initiating the secure connection,
        self.identity = "ALICE"

        # Encrypt g^a mod p
        sensitive_data = str(self.generated_value)
        encrypted_payload = AESCipher(self.shared_secret).encrypt(sensitive_data)
        
        # Format the message to match our protocol
        # "INIT$Alice$R1$E(g^a modp, Kab)"
        message = f"INIT${self.identity}${str(self.nonce)}${encrypted_payload}"
        return message


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        # Check if message starts with one of the protocol tags
        tokenized_msg = message.decode().split("$", 1) 
        return tokenized_msg[0] in ["INIT", "SQCK", "ACKK"]


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):        
        # Set this instance as the receiver
        self.identity = "BOB" if self.identity == None else self.identity
        
        # Check first 4 chars for message type
        msg_type = message.decode()[0:4]
        
        if msg_type == "INIT":
            print("Received INIT")
            # Extract message contents
            tokenized_msg = message.decode().split("$", 3) # Only splits on first three $'s
            sender = tokenized_msg[1]
            challenge = tokenized_msg[2]
            cipher_text = tokenized_msg[3]

            # Enforce directionality
            if sender == self.identity:
                print("Invalid Sender")
                raise ConnectionAbortedError

            # Generate a response to the challenge
            challenge_response = hashlib.sha256(challenge.encode()).hexdigest()
            plain_text = AESCipher(self.shared_secret).decrypt(cipher_text)

            # TODO Maybe sanitize the input here
            self.SetSessionKey((int(plain_text) ** self.secret_exponent) % self.p)

            # Encrypt our identity, g^b mod p, and h(R1)
            sensitive_data = f"{self.identity}${str(self.generated_value)}${challenge_response}"
            encrypted_payload = AESCipher(self.shared_secret).encrypt(sensitive_data)

            # Format the message to match our protocol
            # R2$E("Bob", g^b mod p, h(R1), Kab)
            response = f"SQCK${str(self.nonce)}${encrypted_payload}"
            return response

        elif msg_type == "SQCK":
            print("Received SQCK")
            # Extract message contents
            tokenized_msg = message.decode().split("$", 2) # Only splits on first two $'s
            challenge = tokenized_msg[1]
            cipher_text = tokenized_msg[2]

            # Extract plaintext contents
            plain_text = AESCipher(self.shared_secret).decrypt(cipher_text)
            tokenized_plain_text = plain_text.split("$", 2)
            sender = tokenized_plain_text[0]
            sender_exponent = tokenized_plain_text[1]
            sender_solution = tokenized_plain_text[2]

            # Enforce directionality
            if sender == self.identity:
                print("Invalid Sender")
                raise ConnectionAbortedError

            # Check that challenge was satisfied
            if sender_solution != self.hash_of_nonce:
                print("Received wrong nonce hash")
                raise ConnectionAbortedError

            # TODO Maybe sanitize the input here
            self.SetSessionKey((int(sender_exponent) ** self.secret_exponent) % self.p)

            # Generate a response to the challenge
            challenge_response = hashlib.sha256(challenge.encode()).hexdigest()
            
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
            plain_text = AESCipher(self.shared_secret).decrypt(cipher_text)
            tokenized_plain_text = plain_text.split("$", 1)
            sender = tokenized_plain_text[0]
            sender_solution = tokenized_plain_text[1]

            # Enforce directionality
            if sender == self.identity:
                print("Invalid Sender")
                raise ConnectionAbortedError

            # Check that challenge was satisfied
            if sender_solution != self.hash_of_nonce:
                print("Received wrong nonce hash")
                raise ConnectionAbortedError
            
            return ""

        else:
            print("Received unknown protocol message")
            raise ConnectionAbortedError

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass

    # Helper function for encapsulation
    def GetSessionKey(self):
        return self._key

    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
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
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        # Decrypt the message if a session key has been established
        if self.GetSessionKey():
            message = AESCipher(self.GetSessionKey()).decrypt(cipher_text.decode())
            
            # Extract message contents
            tokenized_message = message.split("$", 1)
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
                print("ERROR: Detected the violation of a message's integrity")
                raise ValueError

        # Otherwise, the connection hasn't been secured yet, so don't decrypt
        return cipher_text
