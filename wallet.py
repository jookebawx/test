import hashlib
import ecdsa
import binascii

INITIAL_BITS = 0x1e777777

class Wallet:
    def __init__(self, name):
        self.name = name
        self.address = "sc"+ hashlib.sha256(name.encode()).hexdigest()[:40]
        self.private_key = ecdsa.SigningKey.generate(curve = ecdsa.SECP256k1)  # generate a new private key
        self.public_key = self.private_key.get_verifying_key()  # get the public key from the private key
        self.signature = self.public_key.to_string("compressed").hex()
        
    
    def sign_transaction(self, transaction):
        message = transaction.encode()  # convert the transaction to a byte string
        signature = binascii.hexlify(self.private_key.sign(message)).decode()  # sign the message and convert the signature to a hex string
        return signature

    def getwalletinfo(self):
        return print("Wallet Data\n Name: "+self.name+"\n address: "+self.address+"\n private key: "+str(self.private_key.to_string().hex())+
                     "\npublic key:"+str(self.signature))
