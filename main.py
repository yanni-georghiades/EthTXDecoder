#!/usr/bin/python
from web3 import Web3


from decoder import (parse_raw_transaction, get_abi_methods, 
	decode_tx_input, get_method_name, decode_logs)

w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/70e46ab7f54a4f209331cb86242805de'))


# Example 1
# tx_hash = '0xc16cf1f97af8f3d174bfcc4c6dad661fad1e8fd9fa7bb496a9ed599f0e70cf64'
# raw_tx = '0x02f8d301820365843b9aca008506fc23ac008302b36894d1e5b0ff1287aa9f9a268759062e4ab08b9dacbe80b86423b872dd00000000000000000000000087f79d1276730019e2b312d372638f888fa737be000000000000000000000000145de1595d3c10168c7f1d22d026da85e50b718cee08f201fab18b982f722f593d642be357c1687afffc998261e012d0b9d0ed2bc001a02756c158f927bce84c0672997042e2d720881991ed3e8a8f653b7c6dceb82371a0134b90a6d6e1a01c579f616ea34208d3f08d3d9fe5b566155740427372482684'

# Example 2
tx_hash = '0x87a3bc85da972583e22da329aa109ea0db57c54a2eee359b2ed12597f5cb1a64'
raw_tx = '0xf9018d8201c185155cfba05183037d16947a250d5630b4cf539739df2c5dacb4c659f2488d80b9012438ed1739000000000000000000000000000000000000000000000000000000009502f900000000000000000000000000000000000000000000a07e38bf71936cbe39594100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000003c02cebb49f6e8f1fc96158099ffa064bbfee38b00000000000000000000000000000000000000000000000000000000616e11230000000000000000000000000000000000000000000000000000000000000003000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000528b3e98c63ce21c6f680b713918e0f89dfae55526a0d6823a6f6496ad3541b8575e4e8deb1d80b391a1948274bd3ae2fef7f554267fa01abfcf0e2578865bf5a0b5f77b7eb635c3c9d50f79f99f9444921bd3d7aca708'

def __main__():
	# parse_raw_transaction currently supports only 1559 and legacy transaction types
    tx = parse_raw_transaction(raw_tx)
    contract = tx.get_destination()

    # get_abi_methods returns a dictionary with pairs abi_methods[function_signature] = abi_json
    abi_methods = get_abi_methods(contract)
    
    # tx_args is a list of input args with values [name, type, value]
    tx_args = decode_tx_input(tx.get_input(), abi_methods)

    # tx_logs is a list of events emitted, each with the same structure as tx_args
    tx_receipt = w3.eth.get_transaction_receipt(tx_hash)
    tx_logs = decode_logs(tx_receipt, abi_methods)


    print('Method: ' + get_method_name(tx, abi_methods))
    print('Input Arguments')
    print('-' * 30)
    for arg in tx_args:
    	print('Argument: ' + arg['name'])
    	print('Type: ' + arg['type'])
    	print('Value: ' + str(arg['value']))
    	print('-' * 4)


    print('Resulting Logs')
    for event_log in tx_logs:
    	print('-' * 30)
    	print('Event: ' + event_log['name'])
    	for arg in event_log['args']:
    		print('-' * 4)
    		print('Argument: ' + arg['name'])
	    	print('Type: ' + arg['type'])
	    	print('Value: ' + str(arg['value']))
	    	
if __name__ == '__main__':
    __main__()