import hashlib
import ecdsa
import binascii
import time
import datetime
import json
import base64

class Wallet:
    def __init__(self, name):
        self.name = name
        self.address = "sc"+ hashlib.sha256(name.encode()).hexdigest()
        self.private_key = ecdsa.SigningKey.generate(curve = ecdsa.SECP256k1)  # generate a new private key
        self.public_key = self.private_key.get_verifying_key()  # get the public key from the private keyy
        self.signature = self.public_key.to_string("compressed").hex()

    def sign_transaction(self, transaction):
        message = transaction.encode()  # convert the transaction to a byte string
        signature = binascii.hexlify(self.private_key.sign(message)).decode()  # sign the message and convert the signature to a hex string
        return signature
    
    def save_to_file(self, filename):
        with open(filename, 'w') as f:
            data = {'name': self.name, 'address': self.address,'private_key': self.private_key.to_string().hex(), 'public_key': self.signature}
            json.dump(data, f)

    def getwalletinfo(self):
        return print("Wallet Data\n Name: "+self.name+"\n private key: "+str(self.private_key.to_string().hex())+
                     "\npublic key:"+str(self.signature))
        
    def load_from_file(cls, filename):
        with open(filename, 'r') as f:
            data = json.load(f)
            return cls(balance=data['balance'], private_key=data['private_key'])
        

class Block:
    def __init__(self, index, data, timestamp, prev_hash, author):
        self.index = index
        self.data = data
        self.prev_hash = prev_hash
        self.author = author
        self.signatures = [Wallet(author).sign_transaction("data")]
        self.timestamp = timestamp
        self.elapsed_time = ""
        self.hash = self.generate_hash()

    def generate_hash(self):
        data_str = str(self.data)  # convert data to string
        sign_str = ''.join(self.signatures)  # concatenate signatures
        block_contents = data_str + self.prev_hash + sign_str  # concatenate block data
        block_hash = hashlib.sha256(block_contents.encode()).hexdigest()
        return block_hash

    def to_json(self):
      return {
        "index" : self.index,
        "prev_hash" : self.prev_hash, 
        "stored_data" : self.data,
        "timestamp" : self.timestamp.strftime("%Y/%m/%d %H:%M:%S"),
        "author" : self.author, 
        "signatures" : self.signatures, 
        "elapsed_time":self.elapsed_time,
        "block_hash" : self.hash
        }


class Blockchain:
    def __init__(self):
        self.authorities = [Wallet("Authority 1"), Wallet("Authority 2"), Wallet("Authority 3")]
        self.blockchain = [self.create_genesis_block()]
        self.required_signatures = 2

    def create_genesis_block(self):
        return Block(0,"Genesis Block", datetime.datetime.now(), "0000000000", "Shin")

    def get_last_block(self):
        return self.blockchain[-1]
        
    def getblockinfo(self, index):
      return print(json.dumps(self.blockchain[index].to_json(), indent=2,sort_keys=True, ensure_ascii = False))
    
    def add_block(self, block):
      self.blockchain.append(block)
    
    def verify_signed_message(self, message, signature, public_key):
        message_bytes = message.encode()
        signature_bytes = base64.b64decode(signature)
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
        valid = vk.verify(signature_bytes, message_bytes, hashfunc=hashlib.sha256)
        return valid

    def mining(self, block):
        approvals = []
        start_time = int(time.time() * 1000)
        for authority in self.authorities:
            approve = input("Enter signature from {} (y/n): ".format(authority.name))
            if approve == 'y':
                approvals.append(authority)
                s = authority.sign_transaction(block.data)
                block.signatures.append(s)
                if not self.verify_signed_message(block.data, s, authority.signature):
                    print("ERROR: SIGNATURE UNVERIFIED")

        if len(approvals)-1 >= self.required_signatures:
            block.prev_hash = self.get_last_block().hash
            block.hash = block.generate_hash()
            end_time = int(time.time()*1000)
            block.elapsed_time = str((end_time - start_time) / (1000.0)) + " s"
            self.add_block(block)
            print("Block added to the blockchain")
        else:
            print("Block not added: insufficient signatures")


# Example usage:
# Initialize the blockchain
bc = Blockchain()

w=Wallet("Samuel")
w.getwalletinfo()

# Add blocks to the chain
bc.mining(Block(1,"Data for Block 1",datetime.datetime.now(), "", w.name))
#bc.mining(Block(2,"Data for Block 2",datetime.datetime.now(), "", "Authority 2"))
#blockchain.add_block(Block("Data for Block 3", "", "Authority 3"))

# Display the blocks in the chain
for block in bc.blockchain :
     print("printing block no " + str(block.index))
     bc.getblockinfo(block.index)

#1. bikin address wallet
#2. tambah validasi signature dan wallet 
#3. database
