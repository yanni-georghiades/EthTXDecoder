from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import keccak
# import web3
# from web3 import Web3
from dataclasses import dataclass, field
from typing import Union, Dict, Sequence, List, Tuple
import requests
import json
import re


ABI_ENDPOINT = 'https://api.etherscan.io/api?module=contract&action=getabi&address='

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
    
        
class Transaction1559Envelope:
    transaction_type: bytes = b'0x02'
    payload: Transaction1559Payload = Transaction1559Payload()

    def get_destination(self):
        return self.payload.destination

    def get_input(self):
        return self.payload.payload

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


def parse_int_from_bytes(b):
    return bytes_to_long(b.lstrip(b'\x00'))

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

    return transaction




def decode_function_signature(signature):
    k = keccak.new(digest_bits=256)
    k.update(signature.encode('utf_8'))
    return k.hexdigest()[:8]


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


def create_abi_method_dict(abi_json):
    methods = {}

    for func_dict in abi_json[1:]:
        function_signature = get_function_signature(func_dict)     
        m_id = decode_function_signature(function_signature)
        methods[m_id] = func_dict

    return methods


def get_abi_methods(contract):
    if not contract.startswith('0x'):
        contract = '0x' + contract
    response = requests.get('%s%s'%(ABI_ENDPOINT, contract))
    response_json = response.json()
    abi_json = json.loads(response_json['result'])
    return abi_json


def decode_tx_input(tx_in, tx_abi_methods):

    if tx_in.startswith("0x"):
        tx_in = tx_in[2:]
    m_id = tx_in[0:8]
    ptr = 8
    
    method = tx_abi_methods[m_id]
    
    tx_args = []
    
    offset = 64

    for arg in method['inputs']:
        print(arg)
        arg_type = arg['internalType']

        if re.match(r'bytes$', arg_type):
            pass
            # num_bytes_remaining = parse_int_from_bytes(tx_in[ptr:ptr + offset])
            # ptr += offset
            # val = []
            # while num_bytes_remaining > 0:
            #     val.append(bytes(tx_in[ptr:ptr + offset]))
            #     ptr += offset
            #     num_bytes_remaining -= 32
        # elif re.match(r'string$', arg_type):
        #     num_bytes_remaining = parse_int_from_bytes(tx_in[ptr:ptr + offset])
        #     ptr += offset
        #     val = []
        #     while num_bytes_remaining > 0:
        #         val.append(bytes(tx_in[ptr:ptr + offset]).decode('utf-8'))
        #         ptr += offset
        #         num_bytes_remaining -= 32
        # dynamic array
        elif re.match(r'\w+\[\]$', arg_type):
            val = []
            temp_ptr = int(tx_in[ptr:ptr + offset].encode(), 16) * 2 + 8
            array_length = int(tx_in[temp_ptr:temp_ptr + offset].encode(), 16)
            temp_ptr += offset
            
            for _ in range(array_length):
                val.append(tx_in[temp_ptr:temp_ptr + offset])
                temp_ptr += offset
        # static array
        # elif re.match(r'\w+\[\d+\]$', arg_type):
        #     val = []
        #     array_length = int(arg_type.split('[')[1][:-1])
        #     for _ in range(array_length):
        #         val.append(tx_in[ptr:ptr + offset])
        #         ptr += offset
        # tuple
        # elif re.match(r'\(.*\)$', arg_type):
            # return 'tuple'
        elif re.match(r'uint\d*$', arg_type):
            val = int(tx_in[ptr:ptr + offset].encode(), 16)
        elif re.match(r'address$', arg_type):
            val = tx_in[ptr:ptr + offset][-40:]
        # elif re.match(r'int\d*$', arg_type):
        #     val = parse_int_from_bytes(tx_in[ptr:ptr + offset])
        # elif re.match(r'bool$', arg_type):
        #     return 'bool'
        # elif re.match(r'fixed\d*x\d*$', arg_type):
        #     val = False if uint256(tx_in[ptr:ptr + offset]) == 0 else 1
        # elif re.match(r'ufixed\d*x\d*$', arg_type):
        #     return 'ufixed'
        else:
            raise ValueError(f'Unknown type {arg_type}')

        
        tx_args.append({'name': arg['name'], 'type': arg_type, 'value': val})
        ptr += offset
    return tx_args


def get_method_name(tx, tx_abi_methods):
    tx_in = tx.get_input()
    if tx_in.startswith("0x"):
        m_id = tx_in[2:10]
    else:
        m_id = tx_in[0:8]

    return tx_abi_methods[m_id]['name']
