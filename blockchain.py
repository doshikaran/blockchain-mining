import random
import time
import socket
import sys
from time import strftime, gmtime
from hashlib import sha256

# Bitcoin Node Configuration
BITCOIN_NODE_IP = '24.86.90.127' #https://bitnodes.io/ 24.86.90.127:8333 /Satoshi:25.1.0/ (Height: 818961)
BITCOIN_NODE_PORT = 8333 
BITCOIN_NODE_ADDRESS = (BITCOIN_NODE_IP, BITCOIN_NODE_PORT)
# Network Socket Configuration
BITCOIN_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
# Blockchain Parameters 
BLOCK_NUMBER = 2,247  # SU ID % 10,000
MAX_NUMBER_OF_BLOCKS = 500  
GENESIS_BLOCK_HASH = bytes.fromhex('000000008752513a044502dd2d75009ff847b5703ce1985f3e9fa8647ec50bbb') #https://www.blockchain.com/explorer/blocks/btc/2247
# Local Node Configuration
LOCAL_IP_ADDRESS = '127.0.0.1'
# Bitcoin Protocol Specifications
PROTOCOL_START_STRING = bytes.fromhex('f9beb4d9')  
PROTOCOL_HEADER_SIZE = 24 
COMMAND_SIZE = 12
VERSION = 70015
EMPTY_BYTE_STRING = ''.encode()  
BUFFER_SIZE = 64000
PREFIX = '  '

# Data Type Conversion Functions
"""
Functions to convert an integer into an unsigned integer of a specific size (in bytes).
"""
def uint8_t(n):
    return int(n).to_bytes(1, byteorder='little', signed=False)
def uint16_t(n):
    return int(n).to_bytes(2, byteorder='little', signed=False)

def uint32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=False)
def uint64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=False)

"""
Functions to convert an integer into a signed integer of a specific size (in bytes).
"""
def int32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=True)
def int64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=True)

# IP Conversion Functions
def ipv6_from_ipv4(ipv4_str):
    """
    Converts an IPv4 address to an IPv6 address.
    """
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))

def ipv6_to_ipv4(ipv6):
    """
    Converts an IPv6 address to an IPv4 address.
    """
    return '.'.join([str(b) for b in ipv6[12:]])

# Unmarshal Functions
def unmarshal_compactsize(b):
    """
    Processes a byte sequence into a 'compactsize' format used in Bitcoin protocols.
    """
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])
def unmarshal_int(b):
    """
    Functions to interpret bytes as signed or unsigned integers.
    """
    return int.from_bytes(b, byteorder='little', signed=True)
def unmarshal_uint(b):
    """
    Functions to interpret bytes as signed or unsigned integers.
    """
    return int.from_bytes(b, byteorder='little', signed=False)

# Other Utility Functions
def swap_endian(b: bytes):
    """
    Converts byte order from big-endian to little-endian or vice versa.
    """
    swapped = bytearray.fromhex(b.hex())
    swapped.reverse()
    return swapped
def sat_to_btc(sat):
    """
    Functions to convert between satoshis and bitcoins.
    """
    return sat * 0.00000001
def btc_to_sat(btc):
    return btc * 10e7
def compactsize_t(n):
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)

def bool_t(flag):
    return uint8_t(1 if flag else 0)

# Bitcoin Protocol Message Functions:   
def build_message(command, payload):
    """
    Constructs a complete Bitcoin protocol message.

    Parameters:
    command (str): The command name (e.g., 'version', 'ping') for the message.
    payload (bytes): The payload of the message as a byte sequence.

    Returns:
    bytes: The complete message ready to be sent over the network, including the message header and payload.
    """
    return message_header(command, payload) + payload

def version_message():
    """
    Constructs a version message payload for the Bitcoin protocol.

    Returns:
    bytes: The payload for a version message, composed of various fields like version number, services, 
    timestamp, network addresses, and other relevant information.
    """
    version = int32_t(VERSION) 
    services = uint64_t(0) 
    timestamp = int64_t(int(time.time())) 
    addr_recv_services = uint64_t(1) 
    addr_recv_ip_address = ipv6_from_ipv4(BITCOIN_NODE_IP)  
    addr_recv_port = uint16_t(BITCOIN_NODE_PORT)
    addr_trans_services = uint64_t(0) 
    addr_trans_ip_address = ipv6_from_ipv4(LOCAL_IP_ADDRESS)  
    addr_trans_port = uint16_t(BITCOIN_NODE_PORT)
    nonce =uint64_t(0)
    user_agent_bytes = compactsize_t(0)  
    start_height = int32_t(0)
    relay = bool_t(False)
    return b''.join([version, services, timestamp,
                     addr_recv_services, addr_recv_ip_address, addr_recv_port,
                     addr_trans_services, addr_trans_ip_address, addr_trans_port,
                     nonce, user_agent_bytes, start_height, relay])


def getdata_message(tx_type, header_hash):
    """
    Constructs a getdata message payload for requesting specific data items from a Bitcoin node.

    Parameters:
    tx_type (int): The type of data being requested (e.g., transaction, block).
    header_hash (bytes): The hash of the block header or transaction.

    Returns:
    bytes: The payload for a getdata message.
    """
    count = compactsize_t(1)
    entry_type =uint32_t(tx_type)
    entry_hash = bytes.fromhex(header_hash.hex())
    return count + entry_type + entry_hash

def getblocks_message(header_hash):
    """
    Constructs a getblocks message payload to request information about blocks.

    Parameters:
    header_hash (bytes): The hash of the latest block header known by the sender.

    Returns:
    bytes: The payload for a getblocks message, including the version, block header hashes, and stop hash.
    """
    version = uint32_t(VERSION)
    hash_count = compactsize_t(1)
    block_header_hashes = bytes.fromhex(header_hash.hex())
    stop_hash = b'\0' * 32
    return b''.join([version, hash_count, block_header_hashes, stop_hash])

def ping_message():
    """
    Constructs a ping message payload for the Bitcoin protocol.

    Returns:
    bytes: The payload for a ping message, consisting of a randomly generated nonce.
    """
    return uint64_t(random.getrandbits(64))

def message_header(command, payload):
    """
    Constructs the header for a Bitcoin protocol message.

    Parameters:
    command (str): The command name for the message.
    payload (bytes): The payload of the message.

    Returns:
    bytes: The header for the message, including the magic value, command name, payload size, and checksum.
    """
    magic = PROTOCOL_START_STRING
    command_name = command.encode('ascii')
    while len(command_name) < COMMAND_SIZE:
        command_name += b'\0'
    payload_size = uint32_t(len(payload))
    check_sum = checksum(payload)
    return b''.join([magic, command_name, payload_size, check_sum])

def checksum(payload: bytes):
    """
    Computes the checksum for a Bitcoin protocol message payload.

    Parameters:
    payload (bytes): The payload of the message.

    Returns:
    bytes: The first four bytes of the double SHA-256 hash of the payload.
    """
    return hash(payload)[:4]

def hash(payload: bytes):
    """
    Computes the double SHA-256 hash of a given payload.

    Parameters:
    payload (bytes): The payload to be hashed.

    Returns:
    bytes: The double SHA-256 hash of the payload.
    """
    return sha256(sha256(payload).digest()).digest()

# Message Parsing and Printing Functions
def print_message(msg, text=None, height=None):
    """
    Prints a Bitcoin protocol message with details such as command, payload, and checksum.

    Parameters:
    msg (bytes): The complete message received from a Bitcoin node.
    text (str, optional): Additional text to prepend to the message header for context.
    height (int, optional): Used in inventory messages to indicate the starting block height.

    Returns:
    str: The command associated with the message.
    """
    print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
    print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
    payload = msg[PROTOCOL_HEADER_SIZE:]
    command = print_header(msg[:PROTOCOL_HEADER_SIZE], checksum(payload))
    if payload:
        header_hash =swap_endian(hash(payload[:80])).hex() if command == 'block' else ''
        print('{}{} {}'.format(PREFIX, command.upper(), header_hash))
        print(PREFIX + '-' * 56)
    if command == 'version':
        print_version_msg(payload)
    elif command == 'sendcmpct':
        print_sendcmpct_message(payload)
    elif command == 'ping' or command == 'pong':
        print_ping_pong_message(payload)
    elif command == 'addr':
        print_addr_message(payload)
    elif command == 'feefilter':
        print_feefilter_message(payload)
    elif command == 'getblocks':
        print_getblocks_message(payload)
    elif command == 'inv' or command == 'getdata' or command == 'notfound':
        print_inv_message(payload, height)
    elif command == 'block':
        print_block_message(payload)
    return command

def print_inv_message(payload, height):
    """
    Prints the details of an 'inv' message payload from the Bitcoin protocol.

    Parameters:
    payload (bytes): The payload of the 'inv' message.
    height (int): The block height from which the inventory is counted.

    Prints the inventory count, type, and hashes.
    """
    count_bytes, count =unmarshal_compactsize(payload)
    i = len(count_bytes)
    inventory = []
    for _ in range(count):
        inv_entry = payload[i: i + 4], payload[i + 4:i + 36]
        inventory.append(inv_entry)
        i += 36
    prefix = PREFIX * 2
    print('{}{:32} Count: {}'.format(prefix, count_bytes.hex(), count))
    for i, (tx_type, tx_hash) in enumerate(inventory, start=height if height else 1):
        print('\n{}{:32} Type: {}\n{}-'.format(prefix, tx_type.hex(),unmarshal_uint(tx_type), prefix))
        block_hash = swap_endian(tx_hash).hex()
        print('{}{:32}\n{}{:32} Block #{} Hash'.format(prefix, block_hash[:32], prefix, block_hash[32:], i))

def print_getblocks_message(payload):
    """
    Prints the details of a 'getblocks' message payload from the Bitcoin protocol.

    Parameters:
    payload (bytes): The payload of the 'getblocks' message.

    Prints the version, hash count, block header hashes, and stop hash.
    """
    version = payload[:4]
    hash_count_bytes, hash_count =unmarshal_compactsize(payload[4:])
    i = 4 + len(hash_count_bytes)
    block_header_hashes = []
    for _ in range(hash_count):
        block_header_hashes.append(payload[i:i + 32])
        i += 32
    stop_hash = payload[i:]
    prefix = PREFIX * 2
    print('{}{:32} Version: {}'.format(prefix, version.hex(),unmarshal_uint(version)))
    print('{}{:32} Hash Count: {}'.format(prefix, hash_count_bytes.hex(), hash_count))
    for hash in block_header_hashes:
        hash_hex =swap_endian(hash).hex()
        print('\n{}{:32}\n{}{:32} Block Header Hash # {}: {}'.format(prefix, hash_hex[:32], prefix, hash_hex[32:], 1,unmarshal_uint(hash)))
    stop_hash_hex = stop_hash.hex()
    print('\n{}{:32}\n{}{:32} Stop Hash: {}'.format(prefix, stop_hash_hex[:32], prefix, stop_hash_hex[32:],unmarshal_uint(stop_hash)))

def print_header(header, expected_cksum=None):
    """
    Prints the header of a Bitcoin protocol message.

    Parameters:
    header (bytes): The header portion of the message.
    expected_cksum (bytes, optional): The expected checksum for verification purposes.

    Prints details such as the magic value, command, payload size, and checksum.
    Returns the command as a string.
    """
    magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'
    prefix = '  '
    print(prefix + 'HEADER')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} Magic:'.format(prefix, magic.hex()))
    print('{}{:32} Command: {}'.format(prefix, command_hex.hex(), command))
    print('{}{:32} Payload Size: {}'.format(prefix, payload_size.hex(), psz))
    print('{}{:32} Checksum {}'.format(prefix, cksum.hex(), verified))
    return command

def print_block_message(payload):
    """
    Prints the details of a Bitcoin block message.

    Parameters:
    payload (bytes): The payload of the block message.

    This function decodes and prints various components of a Bitcoin block such as version, previous block hash,
    merkle root hash, epoch time, difficulty bits, nonce, and transaction count. It also calls `print_transaction` 
    to print transaction details.
    """
    version, prev_block, merkle_root, epoch_time, bits, nonce = \
        payload[:4], payload[4:36], payload[36:68], payload[68:72], payload[72:76], payload[76:80]
    txn_count_bytes, txn_count =unmarshal_compactsize(payload[80:])
    txns = payload[80 + len(txn_count_bytes):]
    prefix = PREFIX * 2
    print('{}{:32} Version: {}\n{}-'.format(prefix, version.hex(),unmarshal_int(version), prefix))
    prev_hash =swap_endian(prev_block)
    print('{}{:32}\n{}{:32} Previous Block Hash\n{}-'.format(prefix, prev_hash.hex()[:32], prefix, prev_hash.hex()[32:], prefix))
    merkle_hash =swap_endian(merkle_root)
    print('{}{:32}\n{}{:32} Merkle Root Hash\n{}-'.format(prefix, merkle_hash.hex()[:32], prefix, merkle_hash.hex()[32:], prefix))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} Epoch Time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} Bits: {}'.format(prefix, bits.hex(),unmarshal_uint(bits)))
    print('{}{:32} Nonce: {}'.format(prefix, nonce.hex(),unmarshal_uint(nonce)))
    print('{}{:32} Transaction Count: {}'.format(prefix, txn_count_bytes.hex(), txn_count))
    print_transaction(txns)

def print_transaction(txn_bytes):
    """
    Prints the details of a single Bitcoin transaction.

    Parameters:
    txn_bytes (bytes): The byte sequence representing a Bitcoin transaction.

    The function parses and prints transaction details including version, transaction inputs, outputs, and lock time.
    It also handles the printing of transaction inputs and outputs through dedicated functions.
    """
    version = txn_bytes[:4]
    tx_in_count_bytes, tx_in_count =unmarshal_compactsize(txn_bytes[4:])
    i = 4 + len(tx_in_count_bytes)
    cb_txn, cb_script_bytes_count = parse_first_transaction(txn_bytes[i:], version)
    tx_in_list = [(cb_txn, cb_script_bytes_count)]
    i += len(b''.join(cb_txn))
    for _ in range(1, tx_in_count):
        tx_in, script_bytes_count = parse_tx_in(txn_bytes[i:])
        tx_in_list.append((tx_in, script_bytes_count))
        i += len(b''.join(tx_in))
    tx_out_count_bytes, tx_out_count = unmarshal_compactsize(txn_bytes[i:])
    tx_out_list = []
    i += len(tx_out_count_bytes)
    for _ in range(tx_out_count):
        tx_out, pk_script_bytes_count = parse_tx_out(txn_bytes[i:])
        tx_out_list.append((tx_out, pk_script_bytes_count))
        i += len(b''.join(tx_out))
    lock_time = txn_bytes[i:i+4]
    prefix = PREFIX * 2
    print('{}{:32} Version: {}'.format(prefix, version.hex(), unmarshal_uint(version)))
    print('\n{}Transaction Inputs:'.format(prefix))
    print(prefix + '-' * 32)
    print('{}{:32} Input txn count: {}'.format(prefix, tx_in_count_bytes.hex(), tx_in_count))
    print_transaction_inputs(tx_in_list)
    print('\n{}Transaction Outputs:'.format(prefix))
    print(prefix + '-' * 32)
    print('{}{:32} Output txn count: {}'.format(prefix, tx_out_count_bytes.hex(), tx_out_count))
    print_transaction_outputs(tx_out_list)
    print('{}{:32} Lock Time: {}'.format(prefix, lock_time.hex(), unmarshal_uint(lock_time)))
    if txn_bytes[i + 4:]:
        print('EXTRA: {}'.format(txn_bytes[i + 4:].hex()))

def print_transaction_inputs(tx_in_list):
    """
    Prints the details of transaction inputs for a Bitcoin transaction.

    Parameters:
    tx_in_list (list): A list of transaction input tuples.

    Each input is printed with details such as the transaction hash, index, script length, signature script, and sequence number.
    """
    prefix = PREFIX * 2
    for i, tx_in in enumerate(tx_in_list, start=1):
        print('\n{}Transaction {}:'.format(prefix, i))
        print(prefix + '*' * 32)
        hash, index, script_bytes, sig_script, seq = tx_in[0]
        script_bytes_count = tx_in[1]
        print('{}{:32}\n{}{:32} Hash\n{}-'.format(prefix, hash.hex()[:32], prefix, hash.hex()[32:], prefix))
        print('{}{:32} Index: {}'.format(prefix, index.hex(),unmarshal_uint(index)))
        print('{}{:32} Script length: {}'.format(prefix, script_bytes.hex(), script_bytes_count))
        print('{}{:32} {}Script'.format(prefix, sig_script.hex(), 'coinbase ' if i == 1 else ''))
        print('{}{:32} Sequence Number:'.format(prefix, seq.hex()))

def print_transaction_outputs(tx_out_list):
    """
    Prints the details of transaction outputs for a Bitcoin transaction.

    Parameters:
    tx_out_list (list): A list of transaction output tuples.

    Each output is printed with details such as the value (in BTC and satoshis), public key script length, and the public key script.
    """
    prefix = PREFIX * 2
    for i, tx_out in enumerate(tx_out_list, start=1):
        print('\n{}Transaction {}:'.format(prefix, i))
        print(prefix + '*' * 32)
        value, pk_script_bytes, pk_script = tx_out[0]
        pk_script_bytes_count = tx_out[1]
        sat= unmarshal_uint(value)
        btc = sat_to_btc(sat)
        print('{}{:32} Value: {} BTC'.format(prefix, value.hex(), sat, btc))
        print('{}{:32} Public key script length: {}\n{}-'.format(prefix, pk_script_bytes.hex(), pk_script_bytes_count, prefix))
        for j in range(0, pk_script_bytes_count * 2, 32):
            print('{}{:32}{}' .format(prefix, pk_script.hex()[j:j + 32],' Public key script\n{}-'.format(prefix) if j + 32 > pk_script_bytes_count * 2 else ''))

# Core Bitcoin Node Interaction Functions
def exchange_messages(bytes_to_send, expected_bytes=None, height=None, wait=False):
    """
    Sends a message to a Bitcoin node and receives the response.

    Parameters:
    bytes_to_send (bytes): The message to be sent to the Bitcoin node.
    expected_bytes (int, optional): The expected number of bytes to receive. If not set, the function waits for a response indefinitely.
    height (int, optional): The block height, used for printing messages.
    wait (bool): If True, wait indefinitely for a response; otherwise, use a timeout.

    Returns:
    list: A list of messages received from the Bitcoin node.
    """
    print_message(bytes_to_send, 'send', height=height)
    BITCOIN_SOCKET.settimeout(0.5)
    bytes_received = b''
    try:
        BITCOIN_SOCKET.sendall(bytes_to_send)
        if expected_bytes:
            while len(bytes_received) < expected_bytes:
                bytes_received += BITCOIN_SOCKET.recv(BUFFER_SIZE)
        elif wait:
            while True:
                bytes_received += BITCOIN_SOCKET.recv(BUFFER_SIZE)
    except Exception as e:
        print('\n No bytes left to receive from {}: {}'.format(BITCOIN_NODE_ADDRESS, str(e)))
    finally:
        print('\n****** Received {} bytes from BTC node {} ******'.format(len(bytes_received), BITCOIN_NODE_ADDRESS))
        peer_msg_list = split_message(bytes_received)
        for msg in peer_msg_list:
            print_message(msg, 'receive', height)
        return peer_msg_list

def send_getblocks_message(input_hash, current_height):
    """
    Sends a 'getblocks' message to a Bitcoin node and processes the received inventory messages.

    Parameters:
    input_hash (bytes): The block hash from which to start requesting block information.
    current_height (int): The current block height.

    Returns:
    tuple: A tuple containing the last 500 block headers and the updated block height.
    """
    getblocks_bytes = build_message('getblocks', getblocks_message(input_hash))
    peer_inv = exchange_messages(getblocks_bytes, expected_bytes=18027, height=current_height + 1)
    peer_inv_bytes = b''.join(peer_inv)
    last_500_headers = [peer_inv_bytes[i:i + 32] for i in range(31, len(peer_inv_bytes), 36)]
    current_height = update_current_height(peer_inv, current_height)
    return last_500_headers, current_height

def peer_height_from_version(vsn_bytes):
    """
    Extracts the peer's block height from a version message.

    Parameters:
    vsn_bytes (bytes): The version message received from a peer.

    Returns:
    int: The block height as reported by the peer.
    """
    return unmarshal_uint(vsn_bytes[-5:-1])

def change_block_value(block, block_number, new_amt):
    """
    Changes the value of the first output transaction in a block and recalculates relevant hashes.

    Parameters:
    block (bytes): The block data.
    block_number (int): The number of the block being modified.
    new_amt (int): The new value (in satoshis) for the first output transaction.

    Returns:
    bytes: The modified block with updated value and recalculated hashes.

    This function is primarily for demonstration and learning purposes.
    """
    txn_count_bytes = unmarshal_compactsize(block[104:])[0]
    index = 104 + len(txn_count_bytes)
    version = block[index:index + 4]
    index += 4
    tx_in_count_bytes = unmarshal_compactsize(block[index:])[0]
    index += len(tx_in_count_bytes)
    tx_in = parse_first_transaction(block[index:], version)[0]
    index += len(b''.join(tx_in))
    txn_out_count_bytes = unmarshal_compactsize(block[index:])[0]
    index += len(txn_out_count_bytes)
    old_value_bytes = block[index:index + 8]
    old_value = unmarshal_uint(old_value_bytes)
    print('Block {}: change value from {} BTC to {} BTC'.format(block_number, sat_to_btc(old_value), sat_to_btc(new_amt)))
    print('-' * 41)
    print('{:<24}'.format('Old Value:') + '{} BTC = {} sat'.format(sat_to_btc(old_value), old_value))
    old_merkle = swap_endian(block[60:92])
    calc_old_merkle =swap_endian(hash(block[104 + len(tx_in_count_bytes):]))
    print('{:<24}'.format('Old Merkle Hash:') + old_merkle.hex())
    print('{:<24}'.format('Verify Old Merkle Hash:') + 'hash(txn) = {}'.format(calc_old_merkle.hex()))
    old_hash = swap_endian(hash(block[PROTOCOL_HEADER_SIZE:PROTOCOL_HEADER_SIZE + 80]))
    print('{:<24}'.format('Old Block Hash:') + old_hash.hex())
    print('*' * 16)
    block = block.replace(block[index:index + 8], uint64_t(new_amt))
    new_value_bytes = block[index:index + 8]
    new_value =unmarshal_uint(new_value_bytes)
    print('{:<24}'.format('New Value:') + '{} BTC = {} sat'.format(sat_to_btc(new_value), new_value))
    calc_new_merkle = hash(block[104 + len(tx_in_count_bytes):])
    block = block.replace(block[60:92], calc_new_merkle)
    new_merkle = swap_endian(block[60:92])
    calc_new_merkle =swap_endian(calc_new_merkle)
    print('{:<24}'.format('New Merkle:') + new_merkle.hex())
    print('{:<24}'.format('Verify New Merkle:') + 'hash(txn) = {}'.format(calc_new_merkle.hex()))
    new_hash =swap_endian(hash(block[PROTOCOL_HEADER_SIZE:PROTOCOL_HEADER_SIZE + 80]))
    print('{:<24}'.format('New Block Hash:') + new_hash.hex())
    print('-' * 32)
    return block

def thief_experiment(my_block, block_number, last_500_blocks, new_value):
    """
    Conducts an experiment to demonstrate altering a block's value in the Bitcoin blockchain.

    Parameters:
    my_block (bytes): The block data to be altered.
    block_number (int): The number of the block being altered.
    last_500_blocks (list): A list of the last 500 block hashes.
    new_value (float): The new value (in BTC) to be set in the block.

    This function modifies the value of a block, recalculates its hash, and compares it with the next block's previous hash to demonstrate the integrity check of the blockchain.
    """
    print('\nBitcoin Thief Experiment')
    print('*' * 64 + '\n')
    btcs = new_value
    sat = btc_to_sat(btcs)
    thief_block = change_block_value(my_block, block_number, sat)
    thief_block = thief_block.replace(thief_block[20:PROTOCOL_HEADER_SIZE], checksum(thief_block[PROTOCOL_HEADER_SIZE:]))
    end = PROTOCOL_HEADER_SIZE + 80
    thief_block_hash = swap_endian(hash(thief_block[PROTOCOL_HEADER_SIZE:end])).hex()
    print_message(thief_block, '*** TEST (value has changed) *** ')
    print('\nBlock # {} data: '.format(block_number + 1))
    next_block_hash = last_500_blocks[(block_number) % 500]
    getdata_msg = build_message('getdata', getdata_message(2, next_block_hash))
    next_block = exchange_messages(getdata_msg, wait=True)
    next_block = b''.join(next_block)
    prev_block_hash =swap_endian(next_block[28:60]).hex()
    print('\nPrevious Block Hash for Block #{}: {}'.format(block_number + 1, prev_block_hash))
    print('Altered Hash for Block #{}: {}'.format(block_number, thief_block_hash))
    print('{} == {} -> {} -> reject!'.format(prev_block_hash, thief_block_hash,prev_block_hash == thief_block_hash))
def print_feefilter_message(feerate):
    """
    Prints the details of a 'feefilter' message from the Bitcoin protocol.

    Parameters:
    feerate (bytes): The feerate value from the 'feefilter' message payload.

    Displays the feerate in a human-readable format.
    """
    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, feerate.hex(),unmarshal_uint(feerate)))

def print_addr_message(payload):
    """
    Prints the details of an 'addr' message from the Bitcoin protocol.

    Parameters:
    payload (bytes): The payload of the 'addr' message.

    Decodes and displays the IP address count, timestamp, services, IP address, and port from the payload.
    """
    ip_count_bytes, ip_addr_count = unmarshal_compactsize(payload)
    i = len(ip_count_bytes)
    epoch_time, services, ip_addr, port = \
        payload[i:i + 4], payload[i + 4:i + 12], \
        payload[i + 12:i + 28], payload[i + 28:]
    prefix = PREFIX * 2
    print('{}{:32} Count: {}'.format(prefix, ip_count_bytes.hex(), ip_addr_count))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} Epoch Time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} Services: {}'.format(prefix, services.hex(),unmarshal_uint(services)))
    print('{}{:32} Host: {}'.format(prefix, ip_addr.hex(), ipv6_to_ipv4(ip_addr)))
    print('{}{:32} Port: {}'.format(prefix, port.hex(), unmarshal_uint(port)))

def print_ping_pong_message(nonce):
    """
    Prints the details of a 'ping' or 'pong' message from the Bitcoin protocol.

    Parameters:
    nonce (bytes): The nonce value from the 'ping' or 'pong' message payload.

    Displays the nonce in a human-readable format.
    """
    prefix = PREFIX * 2
    print('{}{:32} Nonce: {}'.format(prefix, nonce.hex(), unmarshal_uint(nonce)))

def print_sendcmpct_message(payload):
    """
    Prints the details of a 'sendcmpct' message from the Bitcoin protocol.

    Parameters:
    payload (bytes): The payload of the 'sendcmpct' message.

    Decodes and displays the announce flag and version from the payload.
    """
    announce, version = payload[:1], payload[1:]
    prefix = PREFIX * 2
    print('{}{:32} Announce: {}'.format(prefix, announce.hex(), bytes(announce) != b'\0'))
    print('{}{:32} Version: {}'.format(prefix, version.hex(), unmarshal_uint(version)))

def print_version_msg(b):
    """
    Prints the details of a 'version' message from the Bitcoin protocol.

    Parameters:
    b (bytes): The payload of the 'version' message.

    Decodes and displays various fields such as version, services, epoch time, host information, nonce, user agent, and relay flag.
    """
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]
    prefix = PREFIX * 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(),ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(),ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'
          .format(prefix, start_height.hex(),unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))

def parse_first_transaction(cb_bytes, version):
    """
    Parses the first transaction in a Bitcoin block.

    Parameters:
    cb_bytes (bytes): The byte sequence representing the first transaction in a block.
    version (bytes): The version of the block.

    Returns:
    tuple: A tuple containing the parsed transaction elements and the script bytes count. The transaction elements
    include the hash, index, script bytes, (optional) height, coinbase script, and sequence number.
    """
    hash_null = cb_bytes[:32]
    index = cb_bytes[32:36]
    script_bytes, script_bytes_count =unmarshal_compactsize(cb_bytes[36:])
    i = 36 + len(script_bytes)
    height = None
    if unmarshal_uint(version) > 1:
        height = cb_bytes[i:i + 4]
        i += 4
    cb_script = cb_bytes[i:i + script_bytes_count]
    sequence = cb_bytes[i + script_bytes_count: i + script_bytes_count + 4]
    if height:
        return [hash_null, index, script_bytes, height, cb_script, sequence], script_bytes_count
    else:
        return [hash_null, index, script_bytes, cb_script, sequence], script_bytes_count

def parse_tx_out(tx_out_bytes):
    """
    Parses a transaction output in a Bitcoin transaction.

    Parameters:
    tx_out_bytes (bytes): The byte sequence representing a transaction output.

    Returns:
    tuple: A tuple containing the parsed transaction output elements and the public key script bytes count. 
    The transaction output elements include the value, public key script bytes, and the public key script.
    """
    value = tx_out_bytes[:8]
    pk_script_bytes, pk_script_bytes_count = unmarshal_compactsize(tx_out_bytes[8:])
    i = 8 + len(pk_script_bytes)
    pk_script = tx_out_bytes[i:i + pk_script_bytes_count]
    return [value, pk_script_bytes, pk_script], pk_script_bytes_count

def parse_tx_in(tx_in_bytes):
    """
    Parses a transaction input in a Bitcoin transaction.

    Parameters:
    tx_in_bytes (bytes): The byte sequence representing a transaction input.

    Returns:
    tuple: A tuple containing the parsed transaction input elements and the script bytes count. The transaction input
    elements include the hash, index, script bytes, signature script, and sequence number.
    """
    hash = tx_in_bytes[:32]
    index = tx_in_bytes[32:36]
    script_bytes, script_bytes_count =unmarshal_compactsize(tx_in_bytes[36:])
    i = 36 + len(script_bytes)
    sig_script = tx_in_bytes[i:i + script_bytes_count]
    sequence = tx_in_bytes[i + script_bytes_count:]
    return [hash, index, script_bytes, sig_script, sequence], script_bytes_count

def split_message(peer_msg_bytes):
    """
    Splits a sequence of Bitcoin protocol messages into individual messages.

    Parameters:
    peer_msg_bytes (bytes): The byte sequence containing one or more Bitcoin protocol messages.

    Returns:
    list: A list of individual Bitcoin protocol messages.
    """
    msg_list = []
    while peer_msg_bytes:
        payload_size = unmarshal_uint(peer_msg_bytes[16:20])
        msg_size = PROTOCOL_HEADER_SIZE + payload_size
        msg_list.append(peer_msg_bytes[:msg_size])
        peer_msg_bytes = peer_msg_bytes[msg_size:]
    return msg_list

def get_last_block_hash(inv_bytes):
    """
    Retrieves the last block hash from a list of inventory bytes.

    Parameters:
    inv_bytes (bytes): The byte sequence representing a list of block inventories.

    Returns:
    bytes: The hash of the last block in the inventory list.
    """
    return inv_bytes[len(inv_bytes) - 32:]

def update_current_height(block_list, curr_height):
    """
    Updates the current block height based on the received block list.

    Parameters:
    block_list (list): A list of received block hashes.
    curr_height (int): The current block height.

    Returns:
    int: The updated block height.
    """
    if block_list:
        return curr_height + (len(block_list[-1]) - 27) // 36
    else:
        print("Warning: Received empty block list. No height update.")
        return curr_height

def main():
    """
    The main function to run the Bitcoin protocol interaction and block retrieval experiment.

    This function connects to a Bitcoin node, exchanges protocol messages, and retrieves a specific block.
    It then conducts an experiment to demonstrate the alteration of a block's value.
    """
    if len(sys.argv) != 2:
        print('Usage: python3 blockchain.py BLOCK_NUMBER')
        print('Example: python3 blockchain.py 2247')
        exit(1)
    block_number = int(sys.argv[1])

    with BITCOIN_SOCKET:
        BITCOIN_SOCKET.connect(BITCOIN_NODE_ADDRESS)

        version_bytes = build_message('version', version_message())
        peer_vsn_bytes = exchange_messages(version_bytes, expected_bytes=126)[0]
        peer_height = peer_height_from_version(peer_vsn_bytes)

        verack_bytes = build_message('verack', EMPTY_BYTE_STRING)
        exchange_messages(verack_bytes, expected_bytes=202)

        ping_bytes = build_message('ping', ping_message())
        exchange_messages(ping_bytes, expected_bytes=32)

        if block_number > peer_height:
            print('\nCould not retrieve block {}: max height is {}'.format(block_number, peer_height))
            exit(1)

        block_hash = swap_endian(GENESIS_BLOCK_HASH)
        current_height = 0
        last_500_blocks = []
        while current_height < block_number:
            last_500_blocks, current_height = send_getblocks_message(block_hash, current_height)
            if not last_500_blocks:
                print("Error: No blocks received. Exiting.")
                exit(1)
            block_hash = last_500_blocks[-1]
        my_block_hash = last_500_blocks[(block_number - 1) % 500]
        getdata_bytes = build_message('getdata', getdata_message(2, my_block_hash))
        msg_list = exchange_messages(getdata_bytes, height=block_number, wait=True)
        my_block = b''.join(msg_list)
        thief_experiment(my_block, block_number, last_500_blocks, 4000)


if __name__ == '__main__':
    main()