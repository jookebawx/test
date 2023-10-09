import hashlib
import ecdsa
import binascii
import base58
import json
import os
import datetime
import base64

from block import Block


INITIAL_BITS = 0x1e777777

class BlockDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.dict_to_block, *args, **kwargs)

    def dict_to_block(self, dct):
        if all(k in dct for k in ["index", "bits", "nonce", "prev_hash","transactions", "timestamp", "author", "signatures", "elapsed_time", "hash"]):
            iso_timestamp = dct["timestamp"].replace('/', '-').replace(' ', 'T')
            timestamp = datetime.datetime.fromisoformat(iso_timestamp)
            b=Block(dct["bits"], dct["index"], dct["transactions"], timestamp, dct["prev_hash"],dct["author"])
            b.signatures = dct["signatures"]
            b.hash = dct["hash"]
            b.elapsed_time = dct["elapsed_time"]
            return b
        return dct

class BlockEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):  # Check if the object is a datetime instance
            return obj.isoformat()  # Serialize datetime object using ISO format
        elif isinstance(obj, Block):
            return obj.to_json()  # Serialize Block object using its dictionary representation
        return json.JSONEncoder.default(self, obj)

        
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

def generate_private_key():
    key = ecdsa.SigningKey.generate(curve = ecdsa.SECP256k1)
    return key

def str_to_signing_key(key):
    encoded_bytes = base64.b64decode(key)
    signing_key = ecdsa.SigningKey.from_der(encoded_bytes)
    return signing_key

def generate_public_key(priv_key):
    return priv_key.get_verifying_key()

def generate_address(pub_key):
    pubkey_sha256 = hashlib.sha256(pub_key).digest()
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

def get_transaction(address):
    bc = load_blocks()
    tx =[json.dumps(b, indent=2,sort_keys=True, ensure_ascii = False, cls = BlockEncoder) for b in bc if b.author == address or b.tx.get("receiver")== address]
    return tx

def update_balance(address):
    bc = load_blocks()
    tx =[b.tx for b in bc if (b.author == address or b.tx.get("receiver")== address) and b.tx.get("type")=="Crypto"]
    balance = 100
    for t in tx:
        if t.get("receiver") == address:
            balance += t.get("amount")
        else:
            balance -= t.get("amount")
    return balance

def update_docs(address):
    bc = load_blocks()
    tx =[b.tx for b in bc if (b.author == address or b.tx.get("receiver")== address) and b.tx.get("type")=="Docs"]
    docs = [t.get("doc_name") for t in tx]
    return docs
    
def get_doc_link(address):
    bc = load_blocks()
    tx =[b.tx for b in bc if (b.author == address or b.tx.get("receiver")== address) and b.tx.get("type")=="Docs"]
    links = [(t.get("doc_name"),"https://gateway.pinata.cloud/ipfs/%s"%(t.get("ipfs_hash"))) for t in tx]
    return links

def sign_transaction(priv_key,transaction):
        message = str(transaction).encode()  # convert the transaction to a byte string
        signature = binascii.hexlify(priv_key.sign(message)).decode()  # sign the message and convert the signature to a hex string
        return signature