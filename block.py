import hashlib
import ecdsa
import binascii
import time
import datetime
import pickle
import os
import json


from wallet import Wallet
from tx import Transaction

INITIAL_BITS = 0x1e777777
MAX_32BIT = 0xffffffff
AUTH = [Wallet("Authority 1"), Wallet("Authority 2"), Wallet("Authority 3")]


class BlockEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):  # Check if the object is a datetime instance
            return obj.isoformat()  # Serialize datetime object using ISO format
        elif isinstance(obj, Block):
            return obj.__dict__  # Serialize Block object using its dictionary representation
        return json.JSONEncoder.default(self, obj)

# class BlockJSONDecoder(json.JSONDecoder):
#     def __init__(self, *args, **kwargs):
#         json.JSONDecoder.__init__(self, object_hook=self.dict_to_block, *args, **kwargs)

#     def dict_to_block(self, dct):
#         if all(k in dct for k in ["index", "bits", "nonce", "prev_hash","transactions", "timestamp", "author", "signatures", "elapsed_time", "block_hash"]):
#             iso_timestamp = dct["timestamp"].replace('/', '-').replace(' ', 'T')
#             timestamp = datetime.datetime.fromisoformat(iso_timestamp)
#             return Block(dct["bits"], dct["index"], dct["transactions"], timestamp, dct["prev_hash"],dct["author"])
#         return dct
    
class Block:
    def __init__(self, bits, index, tx, timestamp, prev_hash, author):
        self.index = index
        self.bits = bits
        self.nonce = 0
        self.tx = tx
        self.prev_hash = prev_hash
        self.author = author
        self.signatures = [Wallet(author).sign_transaction("data")]
        self.timestamp = timestamp
        self.elapsed_time = ""
        self.hash = ""

    def generate_hash(self):
        tx_str = str(self.tx)  # convert data to string
        sign_str = ''.join(self.signatures)  # concatenate signatures
        block_contents = tx_str + self.prev_hash + sign_str + hex(self.bits)[2:] + str(self.nonce)  # concatenate block data
        h = hashlib.sha256(block_contents.encode()).hexdigest()
        self.hash = h
        return h

    def to_json(self):
      return {
        "index" : self.index,
        "bits" : self.bits,
        "nonce" : self.nonce,
        "prev_hash" : self.prev_hash, 
        "transactions" : self.tx,
        "timestamp" : str(self.timestamp.strftime("%Y/%m/%d %H:%M:%S")),
        "author" : self.author, 
        "signatures" : self.signatures, 
        "elapsed_time":self.elapsed_time,
        "block_hash" : self.hash
        }

    def calc_target(self):
        exponent_bytes = (self.bits >> 24) - 3
        exponent_bits = exponent_bytes * 8
        coefficient = self.bits & 0xffffff
        return coefficient << exponent_bits

    def check_valid_hash(self):
        return int(self.generate_hash(),16) <= self.calc_target()
        

class Blockchain:
    def __init__(self):
        self.authorities = AUTH
        self.blockchain = self.load_blocks()
        self.required_signatures = 2
    
    def create_genesis_block(self):
        return Block(INITIAL_BITS,0,"Genesis Block", datetime.datetime.now(), "0000000000", "Shin").to_json()

    def get_last_block_hash(self):
       return self.blockchain[-1]["block_hash"]
    
    def get_last_block_bits(self):
       return self.blockchain[-1]["bits"]
        
    def getblockinfo(self):
       return print(json.dumps(self.blockchain, indent=2,sort_keys=True, ensure_ascii = False, cls = BlockEncoder))

    
    def add_block(self, block):
        self.blockchain.append(block.to_json())
        self.save_block(self.blockchain)

    
    def verify_signed_message(self, message, signature, public_key): #validate Transaction
        public_key_bytes = binascii.unhexlify(public_key)
        signature_bytes = binascii.unhexlify(signature)
        vk = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
        valid = vk.verify(signature_bytes, message.encode())
        return valid

    def mining(self, block):
        approvals = []
        start_time = int(time.time() * 1000)
        for authority in self.authorities:
            approve = input("Enter signature from {} (y/n): ".format(authority.name))
            if approve == 'y':
                approvals.append(authority)
                s = authority.sign_transaction(block.tx)
                block.signatures.append(s)
                if not self.verify_signed_message(block.tx, s, authority.signature): 
                    print("ERROR: SIGNATURE UNVERIFIED")

        if len(approvals) >= self.required_signatures:
            if len(self.blockchain) < 2:
                block.prev_hash = "000000000"
            else:
               block.prev_hash = self.get_last_block_hash()
            for n in range(MAX_32BIT + 1):
                block.nonce = n
                if block.check_valid_hash():
                    new_bits = self.get_retarget_bits()
                    if new_bits < 0 :
                        if len(self.blockchain) < 2:
                            block.bits = INITIAL_BITS
                        else:
                            block.bits = self.get_last_block_bits()
                    else:
                       block.bits = new_bits
                    end_time = int(time.time()*1000)
                    block.elapsed_time = str((end_time - start_time) / (1000.0)) + "秒"
                    self.add_block(block)
                    print("Block is added to the blockchain")
                    return
        else:
            print("Block is not added: insufficient signatures")

    def get_retarget_bits(self):
      if len(self.blockchain) == 0 or len(self.blockchain) % 5 != 0:
        return -1
      expected_time = 140 * 5

      if len(self.blockchain) != 5:
        first_block = self.blockchain[(1 + 5)]
      else:
        first_block = self.blockchain[0]
      last_block = self.blockchain[-1]
      
      iso_timestamp_1 = first_block["timestamp"].replace('/', '-').replace(' ', 'T')
      first_time = datetime.datetime.fromisoformat(iso_timestamp_1)
      iso_timestamp_2 = last_block["timestamp"].replace('/', '-').replace(' ', 'T')
      last_time = datetime.datetime.fromisoformat(iso_timestamp_2)

      total_time = (last_time - first_time).total_seconds()
      exponent_bytes = (last_block["bits"]>> 24) - 3
      exponent_bits = exponent_bytes * 8
      coefficient = last_block["bits"] & 0xffffff
      target = coefficient << exponent_bits
      delta = total_time / expected_time
      if delta < 0.25:
        delta = 0.25
      if delta > 4:
        delta = 4
      new_target = int(target * delta)

      exponent_bytes = (last_block["bits"]>> 24) -3
      exponent_bits = exponent_bytes * 8
      temp_bits = new_target >> exponent_bits
      if temp_bits != temp_bits & 0xffffff:
        exponent_bytes += 1
        exponent_bits += 8
      elif temp_bits == temp_bits & 0xffff:
        exponent_bytes -= 1
        exponent_bits -= 8
      return ((exponent_bytes + 3) << 24) | (new_target >> exponent_bits) 

    # def is_chain_valid(self):
    #     for i in range(1, len(self.blockchain)):
    #         current_block = self.blockchain[i]
    #         previous_block = self.blockchain[i-1]

    #         # validate the PoW
    #         if not Block.check_valid_hash(current_block["block_hash"]):
    #             print("Current block's hash is not valid")
    #             return False

    #         # validate the PoA
    #         if not len(current_block.signatures) >= self.required_signatures + 1 :
    #             print("Current Block's required signature is not fullfilled")
    #             return False
  
    #         # validate the previous hash
    #         if current_block.prev_hash != previous_block.hash:
    #             print("Current block does not match with the blockchain")
    #             return False     
    #     return True
    
    def load_blocks(self):
        # Load the blocks from a file
        try:
            if os.path.getsize("blocks.dat"):
                with open("blocks.dat", "rb") as f:
                    content = f.read()
                    json_data = json.loads(content.decode('utf-8'))
                    blocks = []
                    for item in json_data:
                        blocks.append(item)
            else:
                blocks = [self.create_genesis_block()]
        except FileNotFoundError:
            blocks = [self.create_genesis_block()]
        return blocks 
       
     
    def save_block(self,block):
        # Save the blocks to a file
        with open("blocks.dat", "wb") as f:
            data=json.dumps(block, default = int)
            f.write(data.encode('utf-8'))