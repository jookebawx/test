from block import Block
from bc import Blockchain
from wallet import Wallet
from tx import Transaction
from mining import Miner
import datetime 
import json
#initialization.0
BC = Blockchain()
m = Miner(BC)
INITIAL_BITS = 0x1e777777
# #block1
# bc.getblockinfo()
w = Wallet("Samuel", 0)
w.getwalletinfo()
# tx1 = Transaction("account", w.address, 0, "Created an account").to_json()
tx1=w.create_wallet()
BC.mining(Block(INITIAL_BITS,BC.get_chain_length(),tx1,datetime.datetime.now(), "", w.address.decode()))
# # #block2
# bc.mining(Block(INITIAL_BITS,bc.get_chain_length(),"Data 1",datetime.datetime.now(), "", w.name))
# bc.getblockinfo()
# print(json.loads(bc.blockchain[3].tx))
# m.mine(Block(INITIAL_BITS,3,"Data 3",datetime.datetime.now(), "", w.name))
BC.getblockinfo()
