import hashlib
import ecdsa
import binascii
import base58
import json
import os
import datetime

from block import Block
from tx import Transaction
INITIAL_BITS = 0x1e777777

class BlockDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.dict_to_block, *args, **kwargs)

    def dict_to_block(self, dct):
        if all(k in dct for k in ["index", "bits", "nonce", "prev_hash","transactions", "timestamp", "author", "signatures", "elapsed_time", "hash"]):
            iso_timestamp = dct["timestamp"].replace('/', '-').replace(' ', 'T')
            timestamp = datetime.datetime.fromisoformat(iso_timestamp)
            return Block(dct["bits"], dct["index"], dct["transactions"], timestamp, dct["prev_hash"],dct["author"])
        return dct
    

        
def load_blocks():
    blocks = []

    # Load the blocks from a file
    try:
        if os.path.getsize("blocks.dat"):
            with open("blocks.dat", "rb") as f:
                blocks_data = json.load(f, cls=BlockDecoder)
                blocks = [b for b in blocks_data if isinstance(b, Block)]
    except FileNotFoundError:
        # Handle the case when the file is not found
        print("File 'blocks.dat' not found.")

    return blocks

chain = load_blocks()

class Wallet:
    def __init__(self, name, pr_type):
        self.name = name
        self.pr_type = pr_type
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
        hash1 = hashlib.sha256(hash).digest()
        hash2 = hashlib.sha256(hash1).digest() 
        
        checksum = hash2[:4] 
        extended_hash =  hash + checksum
        wallet_address = base58.b58encode(extended_hash)
        return wallet_address
    
    def create_wallet(self):
        return Transaction({
        "type" : "create_account",
        "pr_type": self.pr_type,
        "address" : str(self.address),
        "balance": self.balance,
        }).to_json()
    

    def sign_transaction(self, transaction):
        message = str(transaction).encode()  # convert the transaction to a byte string
        signature = binascii.hexlify(self.private_key.sign(message)).decode()  # sign the message and convert the signature to a hex string
        return signature


    def getwalletinfo(self):
        return print("Wallet Data\n Name: "+self.name+"\n address: "+str(self.address)+"\n private key: "+str(self.private_key.to_string().hex())+
                    "\npublic key:"+str(self.signature))
