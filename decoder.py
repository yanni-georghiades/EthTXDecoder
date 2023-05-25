from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import keccak
from dataclasses import dataclass, field
from typing import Union, Dict, Sequence, List, Tuple
import requests
import json
import re
import time


ABI_ENDPOINT = 'https://api.etherscan.io/api?module=contract&action=getabi&address='

# populate the standard erc20 method abi dictionary so we don't have to fetch it
with open('erc20.json', 'r') as f:
        erc20_abi_methods = json.load(f)

class Transaction1559Payload:
    chain_id: int = 0
    signer_nonce: int = 0
    max_priority_fee_per_gas: int = 0
    max_fee_per_gas: int = 0
    gas_limit: int = 0
    destination: int = 0
    amount: int = 0
    payload: bytes = bytes()
    access_list: List[Tuple[int, List[int]]] = field(default_factory=list)
    signature_y_parity: bool = False
    signature_r: int = 0
    signature_s: int = 0
    

# Transaction1559Envelope is a class which encodes EIP-1559 transactions     
class Transaction1559Envelope:
    transaction_type: bytes = b'0x02'
    payload: Transaction1559Payload = Transaction1559Payload()

    def get_destination(self):
        return self.payload.destination

    def get_input(self):
        return self.payload.payload


# TransactionLegacy is a class which encodes legacy type transactions
class TransactionLegacy:
    signer_nonce: int = 0
    gas_price: int = 0
    gas_limit: int = 0
    destination: int = 0
    amount: int = 0
    payload: bytes = bytes()
    v: int = 0
    r: int = 0
    s: int = 0

    def get_destination(self):
        return self.destination

    def get_input(self):
        return self.payload
        
# class Transaction2930Payload:
#     chain_id: int = 0
#     signer_nonce: int = 0
#     gas_price: int = 0
#     gas_limit: int = 0
#     destination: int = 0
#     amount: int = 0
#     payload: bytes = bytes()
#     access_list: List[Tuple[int, List[int]]] = field(default_factory=list)
#     signature_y_parity: bool = False
#     signature_r: int = 0
#     signature_s: int = 0

# class Transaction2930Envelope:
#     type: Literal[1] = 1
#     payload: Transaction2930Payload = Transaction2930Payload()


# parse_int_from_bytes takes a byte string and returns a 64 bit int
def parse_int_from_bytes(b):
    return bytes_to_long(b.lstrip(b'\x00'))


# rlp_decode decodes a string according to the rlp specification
def rlp_decode(string):
    if len(string) == 0:
        return b''
    output = []
    i = 0
    while i < len(string):
        if string[i] <= 0x7f:
            output.append(bytes([string[i]]))
            i += 1
        elif string[i] <= 0xb7:
            length = string[i] - 0x80
            output.append(string[i+1:i+1+length])
            i += 1 + length
        elif string[i] <= 0xbf:
            length_length = string[i] - 0xb7
            length = bytes_to_long(string[i+1:i+1+length_length])
            output.append(string[i+1+length_length:i+1+length_length+length])
            i += 1 + length_length + length
        elif string[i] <= 0xf7:
            length = string[i] - 0xc0
            output.extend(rlp_decode(string[i+1:i+1+length]))
            i += 1 + length
        else:
            length_length = string[i] - 0xf7
            length = bytes_to_long(string[i+1:i+1+length_length])
            output.extend(rlp_decode(string[i+1+length_length:i+1+length_length+length]))
            i += 1 + length_length + length
    return tuple(output) if len(output) > 1 else output[0]


# parse_raw_transaction takes the hex of a raw transaction and returns a transaction object.
# currently this only supports EIP-1559 and legacy transaction types.
def parse_raw_transaction(raw_tx):
    if raw_tx.startswith('0x'):
        raw_tx = bytes.fromhex(raw_tx[2:])
    else:
        raw_tx = bytes.fromhex(raw_tx)
    
    # EIP-2718 transaction
    if raw_tx[0] >= 0x01 and raw_tx[0] <= 0x7f:
        transaction_type = raw_tx[0]
        decoded = rlp_decode(raw_tx[1:])
        
        # EIP-1559 transaction
        if transaction_type == 0x02:
            tx_envelope = Transaction1559Envelope()
            tx_payload = Transaction1559Payload()
            tx_payload.chain_id = parse_int_from_bytes(decoded[0])
            tx_payload.signer_nonce = parse_int_from_bytes(decoded[1])
            tx_payload.max_priority_fee_per_gas = parse_int_from_bytes(decoded[2])
            tx_payload.max_fee_per_gas = parse_int_from_bytes(decoded[3])
            tx_payload.gas_limit = parse_int_from_bytes(decoded[4])
            tx_payload.destination = decoded[5].hex()
            tx_payload.amount = parse_int_from_bytes(decoded[6])
            tx_payload.payload = decoded[7].hex()
            tx_payload.access_list = []
            tx_payload.signature_y_parity = parse_int_from_bytes(decoded[8])
            tx_payload.signature_r = parse_int_from_bytes(decoded[9])
            tx_payload.signature_s = parse_int_from_bytes(decoded[10])
            
            tx_envelope.payload = tx_payload
            return tx_envelope
    elif raw_tx[0] >= 0x7f:
        decoded = rlp_decode(raw_tx)

        tx = TransactionLegacy()
        tx.signer_nonce = parse_int_from_bytes(decoded[0])
        tx.gas_price = parse_int_from_bytes(decoded[1])
        tx.gas_limit = parse_int_from_bytes(decoded[2])
        tx.destination = decoded[3].hex()
        tx.amount = parse_int_from_bytes(decoded[4])
        tx.payload = decoded[5].hex()
        tx.v = parse_int_from_bytes(decoded[6])
        tx.r = parse_int_from_bytes(decoded[7])
        tx.s = parse_int_from_bytes(decoded[8])

        return tx


# decode_function_signature takes the function signature and returns the 4 byte method id
def decode_function_signature(signature):
    k = keccak.new(digest_bits=256)
    k.update(signature.encode('utf_8'))
    return k.hexdigest()[:8]


# get_function_signature takes a method and returns the method prototype 
# (called the signature) which is hashed to find the method id
def get_function_signature(func_dict):
    function_signature = ''
    if 'name' in func_dict.keys():
        function_signature += func_dict['name']
        if 'inputs' in func_dict.keys():
            func_inputs = func_dict['inputs']
            if len(func_inputs) == 0:
                function_signature += "()"
            else:
                function_signature += "("
                for fi in func_inputs:
                    function_signature += fi['type'] + str(',')
                function_signature = function_signature[:-1] + ")"
             
    return function_signature


# create_abi_method_dict takes a list of abi methods and returns a dictionary 
# of methods keyed by the 4 byte method ids
def create_abi_method_dict(abi):
    methods = {}

    for func_dict in abi[1:]:
        function_signature = get_function_signature(func_dict)     
        m_id = decode_function_signature(function_signature)
        methods[m_id] = func_dict

    return methods


# get_abi_methods takes a contract address and returns a dictionary with the abi specification
# as a dictionary, where the keys are the 4 byte method ids of each function
def get_abi_methods(contract):
    if not contract.startswith('0x'):
        contract = '0x' + contract
    response = requests.get('%s%s'%(ABI_ENDPOINT, contract))
    response_json = response.json()
    # Workaround for using rate-limited api

    if response_json['status'] == '0':
        time.sleep(5)
        response = requests.get('%s%s'%(ABI_ENDPOINT, contract))
        response_json = response.json()
    abi_json = json.loads(response_json['result'])
    return create_abi_method_dict(abi_json)


# decode_method_args takes a method abi and a list of raw argument data. 
# it returns a list of decoded arguments with the fields 'name', 'type', 'value'
# currently, it can only decode dynamic length arrays, uints, and addresses
def decode_method_args(method_abi, method_args):
    tx_args = []
    ptr = 0

    for arg in method_abi['inputs']:
        arg_type = arg['internalType']

        if re.match(r'bytes$', arg_type):
            raise ValueError(f'Type {arg_type} not supported')
        elif re.match(r'string$', arg_type):
            raise ValueError(f'Type {arg_type} not supported')
        # dynamic array
        elif re.match(r'\w+\[\]$', arg_type):
            val = []
            temp_ptr = int(int(method_args[ptr].encode(), 16) / 32)
            array_length = int(method_args[temp_ptr].encode(), 16)
            temp_ptr += 1
            
            for _ in range(array_length):
                val.append(method_args[temp_ptr])
                temp_ptr += 1
        # static array
        elif re.match(r'\w+\[\d+\]$', arg_type):
            raise ValueError(f'Type {arg_type} not supported')
        # tuple
        elif re.match(r'\(.*\)$', arg_type):
            raise ValueError(f'Type {arg_type} not supported')
        elif re.match(r'uint\d*$', arg_type):
            val = int(method_args[ptr].encode(), 16)
        elif re.match(r'address$', arg_type):
            val = method_args[ptr][-40:]
        elif re.match(r'int\d*$', arg_type):
            raise ValueError(f'Type {arg_type} not supported')
        elif re.match(r'bool$', arg_type):
            raise ValueError(f'Type {arg_type} not supported')
        elif re.match(r'fixed\d*x\d*$', arg_type):
            raise ValueError(f'Type {arg_type} not supported')
        elif re.match(r'ufixed\d*x\d*$', arg_type):
            raise ValueError(f'Type {arg_type} not supported')
        else:
            raise ValueError(f'Unknown type {arg_type}')

        
        tx_args.append({'name': arg['name'], 'type': arg_type, 'value': val})
        ptr += 1
    return tx_args


# decode_tx_input takes a transaction input and its abi, and returns a list of args.
# Each arg has the fields 'name', 'type', 'value'
def decode_tx_input(tx_in, tx_abi_methods):
    if tx_in.startswith("0x"):
        tx_in = tx_in[2:]
    m_id = tx_in[0:8]
    tx_in = tx_in[8:]
    
    method_abi = tx_abi_methods[m_id]
    method_args = [tx_in[64*i:64*(i+1)] for i in range(int(len(tx_in)/64))]
    return decode_method_args(method_abi, method_args)


# get_method_name takes a transaction and its abi, and returns the name of the method invoked
def get_method_name(tx, tx_abi_methods):
    tx_in = tx.get_input()
    if tx_in.startswith("0x"):
        m_id = tx_in[2:10]
    else:
        m_id = tx_in[0:8]

    return tx_abi_methods[m_id]['name']


# decode_logs takes in the tx receipt and the tx abi methods and returns a list of events.
# Each event has a name and a list of arguments used
def decode_logs(tx_receipt, tx_abi_methods):
    events = []

    tx_logs = tx_receipt['logs']

    for log in tx_logs:

        func_sig = log['topics'][0].hex()[2:10]
        # event_args contains the arguments used by the event emitted
        event_args = [arg.hex() for arg in log['topics'][1:]]
        if log['data'] is not '':
            extra_data = log['data'][2:]
            event_args.extend([extra_data[64*i:64*(i+1)] for i in range(int(len(extra_data)/64))])
        
        # first search for method in the transaction abi (in case we get lucky)
        if func_sig in tx_abi_methods.keys():
            event_abi = tx_abi_methods[func_sig]
        # next search for a standard erc20 method, in case it is being inherited 
        elif func_sig in erc20_abi_methods.keys():
            event_abi = erc20_abi_methods[func_sig]
        # (most expensive) fetch the abi for the contract address of the event
        else:
            # current abi does not contain the event executed, so fetch the correct abi
            event_abi_methods = get_abi_methods(log['address'])
            try:
                event_abi = event_abi_methods[func_sig]
            except:
                print('Unable to find abi methods for this log')

        event_args = decode_method_args(event_abi, event_args)

        events.append({'name': event_abi['name'], 'args': event_args})

    return events


