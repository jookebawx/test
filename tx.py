import json
import base58
import hashlib

class Transaction:

    def __init__(self, tx_type, address, balance, data):
        self.type= tx_type
        if self.verify_wallet_address(address):
            self.address = address
            self.balance = balance
            self.data = data
            self.hash = self.generate_hash()
        else:
            print("invalid")            
        
    
    def to_json(self):
        return json.dumps({
        "type" : self.type,
        "address" : str(self.address),
        "balance": self.balance,
        "data" : self.data, 
        "tx_hash": self.hash
        },  indent=2,sort_keys=True, ensure_ascii = False)
    
    def generate_hash(self):
        tx_content = self.type + str(self.balance) + self.data
        h = hashlib.sha256(tx_content.encode()).hexdigest()
        return h

    def verify_wallet_address(self, address):
        # Decode the wallet address from Base58
        try:
            decoded_address = base58.b58decode(address)
        except ValueError:
            return False

        # Split the decoded address into the hash and the checksum
        checksum = decoded_address[-4:]
        # Calculate the double SHA256 hash of the extended hash
        hash = hashlib.sha256(decoded_address[:-4]).digest()
        hash = hashlib.sha256(hash).digest()
        # Get the first 4 bytes of the double SHA256 hash (the checksum)
        expected_checksum = hash[:4]
        # Verify that the expected checksum matches the actual checksum
        return checksum == expected_checksum

        # Verify that the network prefix matches the expected prefix
        # if hash.startswith(b'sc'):
        #     return True
        # else:
        #     return False

 
