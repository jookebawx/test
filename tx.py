import json

class Transaction:

    def __init__(self, tx_type, address, pub_key, balance, data):
        self.type= tx_type
        self.address = address
        self.pub_key = pub_key
        self.balance = balance
        self.data = data

    def to_json(self):
        return json.dumps({
        "type" : self.type,
        "address" : self.address,
        "pub_key" : self.pub_key,
        "balance": self.balance,
        "data" : self.data, 
        },  indent=2,sort_keys=True, ensure_ascii = False)
    
    def verify_address(self, address):
        if address[2:] != "sc" and len(address)!=20:
            print("ADDRESS IS NOT VALID")
    

 
