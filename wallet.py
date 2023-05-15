import hashlib
import ecdsa
import binascii
import base58

INITIAL_BITS = 0x1e777777

class Wallet:
    def __init__(self, name):
        self.name = name
        self.private_key = ecdsa.SigningKey.generate(curve = ecdsa.SECP256k1)  # generate a new private key
        self.public_key = self.private_key.get_verifying_key().to_string("compressed")
        self.address = self.generate_address()
        self.signature = self.public_key.hex()
        self.balance = 0


    def generate_address(self):
        pubkey_sha256 = hashlib.sha256(self.public_key).digest()
        #add layer of security(anti reverse-engineering + double generate) + reduce length
        ripemd160_hash = hashlib.new('ripemd160') 
        ripemd160_hash.update(pubkey_sha256)
        hash = ripemd160_hash.digest()
        #get checksum to provide integrity, small change = different hash, 
        #to detect and prevent errors when sending cryptocurrency to a wallet address
        hash = hashlib.sha256(hash).digest()
        hash = hashlib.sha256(hash).digest() 
        
        checksum = hash[:4] 
        extended_hash =  hash + checksum
        wallet_address = base58.b58encode(extended_hash)
        return wallet_address


    def sign_transaction(self, transaction):
        message = transaction.encode()  # convert the transaction to a byte string
        signature = binascii.hexlify(self.private_key.sign(message)).decode()  # sign the message and convert the signature to a hex string
        return signature


    def getwalletinfo(self):
        return print("Wallet Data\n Name: "+self.name+"\n address: "+str(self.address)+"\n private key: "+str(self.private_key.to_string().hex())+
                     "\npublic key:"+str(self.signature))
