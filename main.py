from block import Block, Blockchain
from wallet import Wallet
from tx import Transaction
from mining import Miner
import datetime 
#initialization
bc = Blockchain()
m = Miner(bc)
INITIAL_BITS = 0x1e777777
# #block1
w = Wallet("Samuel")
# tx1 = Transaction("account", w.address, w.signature, 0, "Created an account").to_json()
# # w.getwalletinfo()
# bc.mining(Block(INITIAL_BITS,1,tx1,datetime.datetime.now(), "", w.name))
# # #block2
m.mine(Block(INITIAL_BITS,2,"Data 1",datetime.datetime.now(), "", w.name))
# mine(Block(INITIAL_BITS,3,"Data 3",datetyime.datetime.now(), "", w.name),bc)
bc.getblockinfo()
