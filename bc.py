

import time
import datetime
import boto3
import json
import base64
from block import Block

accesskey="QUtJQVdVS09MUUhVUTJBVTM2TVk="
secretkey="SlQwb3ZXazJETzRoc2pCc2VsZVBVd2llRGJLSk0rSk5yUHExUHltMQ=="
s3 = boto3.client(
    's3',
    aws_access_key_id= base64.b64decode(accesskey.encode('utf-8')).decode('utf-8'),
    aws_secret_access_key=base64.b64decode(secretkey.encode('utf-8')).decode('utf-8')
)
S3_BUCKET_NAME = 'arcanabucket123'
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
            b.nonce =dct["nonce"]
            return b
        return dct

        
class Blockchain:
    def __init__(self):
        self.blockchain = self.load_blocks()
    
    def get_chain_length(self):
        return len(self.blockchain)
        
    def getblockinfo(self):
       return print(json.dumps(self.blockchain, indent=2,sort_keys=True, ensure_ascii = False, cls = BlockEncoder))

    def load_blocks(self):
        # Load the blocks from a file
        response= s3.get_object(Bucket=S3_BUCKET_NAME, Key="blocks.dat")
        current_chain_data = response['Body'].read().decode()
        current_chain = json.loads(current_chain_data, cls=BlockDecoder)
        return current_chain