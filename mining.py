from block import Blockchain
import time

MAX_32BIT = 0xffffffff

class Miner:
    def __init__(self,bc):
        self.bc = bc

    def mine(self, block):
        approvals = []
        start_time = int(time.time() * 1000)
        for authority in self.bc.authorities:
            approve = input("Enter signature from {} (y/n): ".format(authority.name))
            if approve == 'y':
                approvals.append(authority)
                s = authority.sign_transaction(block.data)
                block.signatures.append(s)
                if not self.bc.verify_signed_message(block.data, s, authority.signature): 
                    print("ERROR: SIGNATURE UNVERIFIED")

        if len(approvals) >= self.bc.required_signatures:
            if len(self.bc.blockchain) < 2:
                block.prev_hash = "000000000"
            else:
               block.prev_hash = self.bc.get_last_block_hash()
            for n in range(MAX_32BIT + 1):
                block.nonce = n
                if block.check_valid_hash():
                    new_bits = self.bc.get_retarget_bits()
                    if new_bits < 0 :
                        if len(self.bc.blockchain) < 2:
                            block.bits = INITIAL_BITS
                        else:
                            block.bits = self.bc.get_last_block_bits()
                    else:
                       block.bits = new_bits
                    end_time = int(time.time()*1000)
                    block.elapsed_time = str((end_time - start_time) / (1000.0)) + "秒"
                    self.bc.add_block(block)
                    print("Block is added to the blockchain")
                    return
        else:
            print("Block is not added: insufficient signatures")