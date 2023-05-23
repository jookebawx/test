import json
import base58
import hashlib


class Transaction:            
    
    def __init__(self, data):
        self.data = data
        for key in data.keys():
            setattr(self, key, data[key])
        self.tx_hash = self.generate_hash(data)

    def to_json(self):
        # Convert instance variables to dictionary
        data_dict = {}
        for key in self.data.keys():
            data_dict[key] = getattr(self, key)
            if isinstance(data_dict[key], bytes):
                data_dict[key] = data_dict[key].decode('utf-8')
        # Convert dictionary to JSON
        data_dict['tx_hash'] = self.tx_hash
        json_data = json.dumps(data_dict)
        return json_data
    
    # def to_json(self):
    #     return json.dumps({
    #     "type" : self.type,
    #     "address" : str(self.address),
    #     "balance": self.balance,
    #     "data" : self.data, 
    #     "tx_hash": self.hash
    #     })
    
    def generate_hash(self,data):
        tx_content = json.dumps(data)
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

 
