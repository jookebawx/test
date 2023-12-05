import hashlib
import ecdsa
import binascii
import base58
import json

import base64


from bc import *

INITIAL_BITS = 0x1e777777


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
    bc = Blockchain()
    tx =[json.dumps(b, cls = BlockEncoder) for b in bc.blockchain if b.author == address or b.tx.get("receiver")== address]
    return tx

def update_balance(address):
    bc = Blockchain()
    tx =[b.tx for b in bc.blockchain if (b.author == address or b.tx.get("receiver")== address) and b.tx.get("type")=="Crypto"]
    balance = 100
    for t in tx:
        if t.get("receiver") == address:
            balance += t.get("amount")
        else:
            balance -= t.get("amount")
    return balance

def update_docs(address):
    bc = Blockchain()
    tx =[b.tx for b in bc.blockchain if (b.author == address or b.tx.get("receiver")== address) and b.tx.get("type")=="Docs"]
    docs = [t.get("doc_name") for t in tx]
    return docs
    
def get_doc_link(address):
    bc = Blockchain()
    tx =[b.tx for b in bc.blockchain if (b.author == address or b.tx.get("receiver")== address) and b.tx.get("type")=="Docs"]
    links = [(t.get("doc_name"),"https://gateway.pinata.cloud/ipfs/%s"%(t.get("ipfs_hash"))) for t in tx]
    return links

def sign_transaction(priv_key,transaction):
        message = str(transaction).encode()  # convert the transaction to a byte string
        signature = binascii.hexlify(priv_key.sign(message)).decode()  # sign the message and convert the signature to a hex string
        return signature