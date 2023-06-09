
import ecdsa
import binascii
import time
import datetime
import os
import json

from block import Block
from wallet import Wallet
from tx import Transaction

INITIAL_BITS = 0x1e777777
MAX_32BIT = 0xffffffff
# AUTH = [Wallet("Authority 1",1), Wallet("Authority 2",1), Wallet("Authority 3",1)]


class BlockEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):  # Check if the object is a datetime instance
            return obj.isoformat()  # Serialize datetime object using ISO format
        elif isinstance(obj, Block):
            return obj.to_json()  # Serialize Block object using its dictionary representation
        return json.JSONEncoder.default(self, obj)

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

        
class Blockchain:
    def __init__(self):
        # self.authorities = AUTH
        self.blockchain = self.load_blocks()
        self.required_signatures = 2
    
    def create_genesis_block(self):
        return Block(INITIAL_BITS,0,"Genesis Block", datetime.datetime.now(), "", "Shin").to_json()
    
    def get_chain_length(self):
        return len(self.blockchain)
    
    def get_last_block_hash(self):
       return self.blockchain[-1]["block_hash"]
    
    def get_block_address(self,block):
       return block.tx.address
        
    def getblockinfo(self):
       return print(json.dumps(self.blockchain, indent=2,sort_keys=True, ensure_ascii = False, cls = BlockEncoder))

    
    def add_block(self, block):
        self.blockchain.append(block)
        self.save_block(self.blockchain)

    
    def verify_signed_message(self, message, signature, public_key): #validate Transaction
        public_key_bytes = binascii.unhexlify(public_key)
        signature_bytes = binascii.unhexlify(signature)
        vk = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
        valid = vk.verify(signature_bytes, str(message).encode())
        return valid

    def mining(self, block):
        # approvals = []
        # start_time = int(time.time() * 1000)
        # for authority in self.authorities:
        #     approve = input("Enter signature from {} (y/n): ".format(authority.name))
        #     if approve == 'y':
        #         approvals.append(authority)
        #         s = authority.sign_transaction(block.tx)
        #         block.signatures.append(s)
        #         if not self.verify_signed_message(block.tx, s, authority.signature): 
        #             print("ERROR: SIGNATURE UNVERIFIED")
        # if len(approvals) >= self.required_signatures:
        block.prev_hash = self.blockchain[-1].hash
        start_time = int(time.time() * 1000)
        for n in range(MAX_32BIT + 1):
            block.nonce = n
            if block.check_valid_hash():
                new_bits = self.get_retarget_bits()
                if new_bits < 0 :
                    if len(self.blockchain) < 2:
                        block.bits = INITIAL_BITS
                    else:
                        block.bits = self.blockchain[-1].bits
                else:
                    block.bits = new_bits
                end_time = int(time.time()*1000)
                block.elapsed_time = str((end_time - start_time) / (1000.0)) + "秒"
                self.add_block(block)
                print("Block is added to the blockchain")
                return
        # else:
        #     print("Block is not added: insufficient signatures")

    def get_retarget_bits(self):
      if len(self.blockchain) == 0 or len(self.blockchain) % 5 != 0:
        return -1
      expected_time = 140 * 5

      if len(self.blockchain) != 5:
        first_block = self.blockchain[(1 + 5)]
      else:
        first_block = self.blockchain[0]
      last_block = self.blockchain[-1]

      first_time = first_block.timestamp.timestamp()
      last_time = last_block.timestamp.timestamp()
      total_time = last_time - first_time
      
      target = last_block.calc_target()
      
      delta = total_time / expected_time
      if delta < 0.25:
        delta = 0.25
      if delta > 4:
        delta = 4
      new_target = int(target * delta)

      exponent_bytes = (last_block.bits >> 24) -3
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
                    blocks_data = json.load(f, cls=BlockDecoder)
                    blocks = [b for b in blocks_data if isinstance(b, Block)]
            else:
                blocks = [Block(INITIAL_BITS,0,{"type":"Genesis Block"}, datetime.datetime.now(), "", "Shin")]
        except FileNotFoundError:
            blocks = [Block(INITIAL_BITS,0,{"type":"Genesis Block"}, datetime.datetime.now(), "", "Shin")]
        return blocks 
       
     
    def save_block(self,block):
        # Save the blocks to a file
        with open("blocks.dat", "wb") as f:
            data=json.dumps(block, cls = BlockEncoder)
            f.write(data.encode('utf-8'))