import datetime
import json
import hashlib
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse



class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof=1, PreviousHash='0')
        self.nodes = set()


    def create_block(self, proof, PreviousHash):
        block = {'Index': len(self.chain) + 1,
                 'Timestamp': str(datetime.datetime.now()),
                 'Proof': proof,
                 'PreviousHash': PreviousHash,
                 'Transactions': self.transactions}

        self.transactions = []

        self.chain.append(block)
        return block


    def get_previous_block(self):
        return self.chain[-1]


    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False

        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()

            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
                
        return new_proof


    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        
        return hashlib.sha256(encoded_block).hexdigest()


    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]

            if block['PreviousHash'] != self.hash(previous_block):
                return False
            
            previous_proof = previous_block['Proof']
            proof = block['Proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()

            if hash_operation[:4] != '0000':
                return False

            previous_block = block
            block_index += 1

        return True


    def add_transaction(self, sender, receiver, amount):
        self.transactions.append({'Sender': sender,
                                  'Receiver': receiver,
                                  'Amount': amount})
        
        previous_block = self.get_previous_block()

        return previous_block['Index'] + 1


    def add_node(self, address):
        parsed_url = urlparse(address)

        self.nodes.add(parsed_url.netloc)


    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)

        for node in network:
            response = requests.get(f'http://{node}/getchain')

            if  response.status_code == 200:
                length = response.json()['Length']
                chain = response.json()['Chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain

            if longest_chain:
                self.chain = longest_chain
                return True
            else:
                return False



app = Flask(__name__)



node_address = str(uuid4()).replace('-', '')



blockchain = Blockchain()



@app.route('/mineblock', methods=['GET'])


def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['Proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    blockchain.add_transaction(sender=node_address, receiver='Abeer', amount=2)

    block = blockchain.create_block(proof, previous_hash)

    response = {'Message': 'Mine Successful!',
                'Index': block['Index'],
                'Timestamp': block['Timestamp'],
                'Proof': block['Proof'],
                'PreviousHash': block['PreviousHash'],
                'Transactions': block['Transactions']}

    return jsonify(response), 200



@app.route('/isvalid', methods=['GET'])


def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'Message': 'Blockchain is valid'}
    else:
        response = {'Message': 'Blockchain is not valid'}

    return jsonify(response), 200



@app.route('/getchain', methods=['GET'])


def get_chain():
    response = {'Chain': blockchain.chain,
                'Length': len(blockchain.chain)}

    return jsonify(response), 200



@app.route('/addtransaction', methods=['POST'])


def add_transaction():
    json = request.get_json()
    transaction_keys = ['Sender', 'Receiver', 'Amount']

    if not all (key in json for key in transaction_keys):
        return 'Some element is missing', 400
    
    index = blockchain.add_transaction(json['Sender'], json['Receiver'], json['Amount'])

    response = {'Message': f'This transaction will be added to Block {index}'}

    return jsonify(response), 201



@app.route('/connectnode', methods=['POST'])


def connect_node():
    json = request.get_json()
    nodes = json.get('Nodes')

    if nodes is None:
        return 'No node', 400
    
    for node in nodes:
        blockchain.add_node(node)

    response = {'Message': 'All the nodes have been added and connected, the total nodes are:',
                'Total Nodes': list(blockchain.nodes)}

    return jsonify(response), 201



@app.route('/replacechain', methods=['GET'])


def replace_chain():
    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        response = {'Message': 'The nodes had different chains. The longest one was crowned king',
                    'New Chain': blockchain.chain}
    else:
        response = {'Message': 'All is good',
                    'Chain': blockchain.chain}

    return jsonify(response), 200



app.run(host='0.0.0.0', port=5001)