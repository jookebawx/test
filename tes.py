import hashlib 

def sha256(data): 
    return hashlib.sha256(data.encode()).hexdigest()

class MerkleTree(): 

  def __init__(self, tx_list):
    self.tx_list = tx_list
  
  def calc_merkleroot(self):
    txs= self.tx_list
    if len(txs) == 1:
      return txs[0]
    while len(txs) > 1:
      if len(txs)%2 == 1:
        txs.append(txs[-1])
      hashes = []
      for i in range(0, len(txs), 2):
        hashes.append(sha256("".join(txs [i:i+2])))
      txs = hashes
    return txs[0]
  
if __name__ == "__main__":
    txs = [
      "e7c6a5c20318e99e7a2fe7e9c534fae52d402ef6544afd85a0a1a22a8d9783a",
      "3fe7ac92b9d20c9b5fb1ba21008b41eb1208af50a7021694f7f73fd37e914b67",
      "b3a37d774cd5f15be1ee472e8c877bcc54ab8ea00f25d34ef11e76a17ecbb67c",
      "dcc75a59bcee8a4617b8f0fc66d1444fea3574addf9ed1e0631ae85ff6c65939",
      "59639ffc15ef30860d11da02733c2f910c43e600640996ee17f0b12fd0cb51e9",
      "0e942bb178dbf7ae40d36d238d559427429641689a379fc43929f15275a75fa6",
      "5ea33197f7b956644d75261e3c03eefeeea43823b3de771e92371f3d630d4c56",
      "55696d0a3686df2eb51aae49ca0a0ae42043ea5591aa0b6d755020bdb64887f6",
      "2255724fd367389c2aabfff9d5eb5d08eda0d7fed01f3f9d0527693572c08f6",
      "c8329c18492c5f6ee61eb56dab52576b1de48bbb1d7f6aa7f0387f9b3b63722e",
      "34b7f053f77406456676fdd3d1e4ac858b69b54daf3949806c2c92ca70d3b88d"
      ]

    m = MerkleTree(txs) 
    print(m.calc_merkleroot())
  