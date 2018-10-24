# Reference: http://adilmoujahid.com/posts/2018/03/intro-blockchain-bitcoin-python/
# Run in Python 2
# Array problem: https://stackoverflow.com/questions/18931315/typeerror-string-indices-must-be-integers-not-str-working-with-dict

#!/usr/bin/python3
import json
import copy
import time
import random
import hashlib
import os
import binascii
from flask import Flask, request, Response

app = Flask(__name__)
walletIdentifier = 0 # wallet identifier

class Blockchain:

    def __init__(self):
        self.chain = []
        self.wallets = {}
        self.mempool = {}
        self.difficulty_target = 4
        self.mine_block()

#NEW-----------------------------------------------------------------------------------------------------

    def create_wallet(self):
        # define wallet with fields: public_key, private_key, balance
        public_key = binascii.b2a_hex(os.urandom(8))
        private_key = binascii.b2a_hex(os.urandom(8))
        balance = float(10)

        new_wallet = {
            'public_key' : public_key,
            'private_key' : private_key,
            'balance' : balance
        }

        # add new wallet to self.wallets
        global walletIdentifier # wallet reference ID
        walletIdentifier += 1
        self.wallets.update({str(walletIdentifier) : new_wallet})

        # return the wallet to caller
        return new_wallet

    def hash_transaction(self, transaction):
        # hash transaction
        hash_id = hashlib.sha256()
        hash_id.update(repr(transaction).encode('utf-8'))

        # return hash
        return str(hash_id.hexdigest())

    def add_transaction_to_mempool(self, transaction_id, transaction):
        # validate transaction
            # check private key of sender (validation)
        # add transaction to self.mempool
            # add transaction as object in a dict() holding pending transactions (adding)
        # return OK or BAD
        pass

    def choose_transactions_from_mempool(self):
        # choose 10 random transactions
        # check if the balances allow spending the amount
        # change the balance for the sender
        # change the balance for the recipient
        # remove transactions from mempool
        # return transaction to caller
        pass


    def calculate_merkle_root(self, block):
        # calculate the merkle root
        # return the merkle root (hash)
        pass


    def check_merkle_root(self, block):
        # check merkle root
        # return OK or BAD
        pass


#--------------------------------------------------------------------------------------------------------


    def hash_block_header(self, block):
        hashId = hashlib.sha256()
        hashId.update(repr(block['header']).encode('utf-8'))
        return str(hashId.hexdigest())

    def get_last_block(self):
        return self.chain[-1]

    def create_block(self):

        block = {
            'header' : {
                'block_number': len(self.chain),
                'block_time': int(time.time()),
                'block_nonce': None,
                'previous_block_hash': (None if len(self.chain) == 0 else self.get_last_block()['hash']),
                'merkle_root': None
            },
            'transactions' : {},
            'hash' : None
        }

        return block


    def mine_block(self):

        block = self.create_block()

        block['transactions'] = self.choose_transactions_from_mempool()
        block['header']['merkle_root'] = self.calculate_merkle_root(block)

        while True:
            block['header']['block_nonce'] = str(binascii.b2a_hex(os.urandom(8)))
            block['hash'] = self.hash_block_header(block)

            if block['hash'][:self.difficulty_target] == '0' * self.difficulty_target:
                break

        self.chain.append(block)

        return block


    def check_chain(self):

        for block_number in reversed(range(len(self.chain))):

            current_block = self.chain[block_number]

            if not current_block['hash'] == self.hash_block_header(current_block):
                return False

            if block_number > 0 and not current_block['header']['previous_block_hash'] == self.chain[block_number - 1]['hash']:
                return False

            if not self.check_merkle_root(current_block):
                return False

        return True


#NEW-----------------------------------------------------------------------------------------------------


@app.route('/create_wallet', methods = ['GET'])
def create_wallet():
    return Response(json.dumps(blockchain.create_wallet()), status=200, mimetype='application/json')

@app.route('/show_balances', methods = ['GET'])
def show_balances():
    # clean wallets of private_keys here

    # create empty array for each clean_wallet
    clean_wallets = {}
    for wallet in blockchain.wallets:

        # add contents to clean_wallet
        clean_wallet = {
            "public_key" : blockchain.wallets[wallet]["public_key"],
            "balance" : blockchain.wallets[wallet]["balance"]
        }

        # insert clean_wallet into clean_wallets array
        clean_wallets.update({str(wallet) : clean_wallet})

    # returns clean_wallets and sorts keys (otherwise dict won't be in order)
    return Response(json.dumps(clean_wallets, sort_keys = True), status=200, mimetype='application/json')

# Function used to show private keys (intentionally left here for testing)
@app.route('/show_private', methods = ['GET'])
def show_private():
    return Response(json.dumps(blockchain.wallets), status=200, mimetype='application/json')

@app.route('/create_transaction', methods = ['GET'])
# http://0.0.0.0:8080/create_transaction?from=<sender>&to=<receiver>&amount=<float>&private_key=<priv>

def create_transaction():

    try:

        transaction = {
            'time': int(time.time()),
            'from': request.args.get('from', type = str),
            'to': request.args.get('to', type = str),
            'amount': request.args.get('amount', type = float)
        }

        private_key = request.args.get('private_key', default = '', type = str)
        assert private_key == blockchain.wallets[transaction['from']]['private_key']

    except:
        return Response(json.dumps({'Error': 'Invalid transaction'}), status=400, mimetype='application/json')

    transaction_id = blockchain.hash_transaction(transaction)
    transaction_ok = blockchain.add_transaction_to_mempool(transaction_id, transaction)

    if transaction_ok:
        return Response(json.dumps({'Result': transaction_id}), status=200, mimetype='application/json')
    else:
        return Response(json.dumps({'Error': 'Invalid transaction'}), status=400, mimetype='application/json')

@app.route('/show_mempool', methods = ['GET'])
def show_mempool():
    return Response(json.dumps(blockchain.mempool), status=200, mimetype='application/json')


#--------------------------------------------------------------------------------------------------------


@app.route('/mine_block', methods = ['GET'])
def mine_block():
    block = blockchain.mine_block()
    return Response(json.dumps(block), status=200, mimetype='application/json')


@app.route('/check_blockchain', methods = ['GET'])
def check_blockchain():
    if blockchain.check_chain:
        return Response(json.dumps({'Result': 'OK'}), status=200, mimetype='application/json')
    else:
        return Response(json.dumps({'Result': 'Invalid blockchain'}), status=200, mimetype='application/json')


@app.route('/show_blocks', methods = ['GET'])
def show_blocks():
    return Response(json.dumps(blockchain.chain), status=200, mimetype='application/json')


@app.route('/show_block', methods = ['GET'])
def show_block():
    try:
        block_number = request.args.get('number', default = 0, type = int)
        block = blockchain.chain[block_number]
    except:
        return Response(json.dumps({'Error': 'Invalid block number'}), status=400, mimetype='application/json')

    return Response(json.dumps(block), status=200, mimetype='application/json')


#--------------------------------------------------------------------------------------------------------

blockchain = Blockchain()
app.run(host = '0.0.0.0', port = 8080)
