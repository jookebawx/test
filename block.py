import hashlib

class Block:
    def __init__(self, bits, index, tx, timestamp, prev_hash, author):
        self.index = index
        self.bits = bits
        self.nonce = 0
        self.tx = tx
        self.prev_hash = prev_hash
        self.author = author
        self.signatures = []
        self.timestamp = timestamp
        self.elapsed_time = ""
        self.hash = ""

    def generate_hash(self):
        tx_str = str(self.tx)  # convert data to string
        sign_str = ''.join(self.signatures)  # concatenate signatures
        block_header = str(self.index) + tx_str + self.prev_hash + sign_str + str(self.nonce)  # concatenate block data
        h = hashlib.sha256(block_header.encode()).hexdigest()
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
        "hash" : self.hash
        }

    def calc_target(self):
        exponent_bytes = (self.bits >> 24) - 3
        exponent_bits = exponent_bytes * 8
        coefficient = self.bits & 0xffffff
        return coefficient << exponent_bits

    def check_valid_hash(self):
        return int(self.generate_hash(),16) <= self.calc_target()
