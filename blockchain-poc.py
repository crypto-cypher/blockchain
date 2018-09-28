#!/usr/bin/python3
# Referenced tutorial: https://hackernoon.com/learn-blockchains-by-building-one-117428612f46
# Referenced code: https://github.com/dvf/blockchain/blob/master/blockchain.py

"""
NOTE FOR PROFESSOR:
When we were writing this, we learned from a few tutorials.
The tutorials that I used had "proof" IDs where the hash verification was done.

We ended up getting stuck & verified with proofs instead of header hashes. ¯\_(ツ)_/¯

Things to know:
- Provides immutability for data inserted into blocks using SHA256
- Links between blocks using block hashes (using proofs!)
- Each block still contains a hash of the previous block
- A nonce of "0000" is used within proof_of_work() proofs
- Hashes won't show leading "0000" in the Blockchain, but they are in proofs
- All functions should work as expected, regardless of small differences

Functions for testing:
GET http://127.0.1.1:8080/mine_block?data=<"data to add">
GET http://127.0.1.1:8080/get_blocks
GET http://127.0.1.1:8080/get_block?index=<block number> (defaults int 0)
GET http://127.0.1.1:8080/check_blockchain
"""

import hashlib
import json
from time import time
from flask import Flask, jsonify, request

# Represent a blockchain with a class
class Blockchain(object):
    def __init__(self):
        self.chain = []

        # Create genesis block
        self.create_block(previous_hash = '1', proof = 100)

    def create_block(self, proof, previous_hash = None, data = None):
        # Creates a new block
        # Add block to chain
        """
        Create a new block in the Blockchain

        :proof: <int> The proof given by the Proof of Work algorithm
        :previous_block_hash: (Optional) <str> Hash of previous Block
        :return: <dict> New Block
        """

        block = {
            'header' : {
                'block_number' : len(self.chain),
                'block_time' : time(),
                'proof' : proof,
                'previous_block_hash' : previous_hash or self.hash(self.chain[-1]),
            },
            'data' : data,
            'hash' : '', # intentionally left blank, used proofs instead
        }

        self.chain.append(block)
        return block

    @property
    def last_block(self):
        # [-1] returns chain's last Block
        return self.chain[-1]

    @staticmethod
    def hash(block):
        # Hashes a block
        """
        Create a SHA-256 hash of a Block

        :block: <dict> block
        :return: <str>
        """

        # Dict must be Ordered, or there may be inconsistency in hashes?
        block_string = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Proof of Work Algorithm:
        - "Find a number p' such that hash (pp') contains leading 4 zeroes, where p is the previous p'"
        - "p is the previous proof, and p' is the new proof"

        :last_proof: <int>
        :return: <int>
        """

        last_proof = last_block['header']['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        # correctHash is the correct hash solution with leading "0000" nonce
        # useless in this program, but this would normally be the hash
        # used in the block's 'header' -- just pointing that out
        correctHash = self.valid_proof(last_proof, proof, last_hash)

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        # Check if the proof given is valid, per "0000" nonce requirement
        """
        Validates the Proof:
        Checks if hash(last_proof, proof) has 4 leading zeroes

        :last_proof: <int> Previous Proof
        :proof: <int> Current Proof
        :last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.
        """

        # Nonce complexity level (only accepts nonce of "0000" by default)
        difficulty_target = 4
        nonce = "0"*difficulty_target

        # Proof of work validation
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty_target] == nonce

    def check_chain(self, chain):
        # Verify blockchain legitimacy
        """
        "Determine if a given blockchain is valid"
        :chain: <list> A blockchain
        :return: <bool> True if valid, False if not
        """

        genesis_block = chain[0]
        current_index = 1
        block_counter = 0

        while current_index < len(chain):
            block = chain[current_index]
            block_counter += 1
            print(f'{genesis_block}')
            print(f'{block}')

            # Check that the hash of the block is correct
            genesis_block_hash = self.hash(genesis_block)
            if block['header']['previous_block_hash'] != self.hash(genesis_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(genesis_block['header']['proof'], block['header']['proof'], genesis_block_hash):
                return False

            # Announce "block n verified"
            print(f'\nblock '+str(block_counter)+' verified')
            print("\n-------------------------------\n")

            genesis_block = block
            current_index += 1

        return True

# Create Node using Flask
app = Flask(__name__)

# Mine a new block
@app.route('/mine_block', methods=['GET'])
def mine_block():
    # GET https://127.0.1.1:8080/mine_block?data=<data to add>

    # Run the proof of work algorithm to get the next proof
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # Create the new Block, add it to the chain
    block_data = request.args.get('data', default = '', type = str)
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(proof, previous_hash, block_data)

    response = {
        'message' : "New Block Created",
        'block_number' : str(block['header']['block_number']),
        'block_time' : str(block['header']['block_time']),
        'proof' : str(block['header']['proof']),
        'previous_block_hash' : str(block['header']['previous_block_hash']),
        'data' : block['data']
    }

    return jsonify(response), 200

# Validate the blockchain's legitimacy
@app.route('/check_blockchain', methods = ['GET'])
def check_blockchain():
    # GET https://127.0.1.1:8080/check_blockchain

    blockCheck = blockchain.check_chain(blockchain.chain)
    if blockCheck == True:
        response = {
            'blockchain verification' : 'successful',
            'blockchain length' : len(blockchain.chain),
            }
    else:
        response = {
            'blockchain verification' : 'failed',
            'blockchain length' : len(blockchain.chain),
            }

    return jsonify(response), 200

# Print the all blocks of the blockchain
@app.route('/get_blocks', methods=['GET'])
def get_blocks():
    # GET https://127.0.1.1:8080/get_blocks

    response = {
        'chain' : blockchain.chain,
        'blockchain length' : len(blockchain.chain),
    }

    return jsonify(response), 200

# Print one block of the blockchain
@app.route('/get_block', methods = ['GET'])
def get_block():
    # GET http://127.0.1.1:8080/get_block?index=<block number>

    try:
        # 'block request' returns a print of a specified block
        index = request.args.get('index', default = 0, type = int)
        response = { 'block request': blockchain.chain[index] }
    except:
        return 'Error: This block index number does not exist!\n', 400

    return jsonify(response), 200

if __name__ == '__main__':
    blockchain = Blockchain()
    app.run(host = '127.0.1.1', port=8080)
