# ---------------------------------------------------
# Example for Server w/ socket SSL communication 
# ---------------------------------------------------
# Creator   : Ilias Papalamprou
# Date      : 12/2023
# ---------------------------------------------------
import socket
import ssl
import Crypto.Random
from ecdh import DiffieHellman, get_key_hex, get_key_object
from ecdsa import SigningKey, NIST256p, VerifyingKey
from colorama import Fore, init
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

from binascii import hexlify, unhexlify 

# from kyber import Kyber512
import os

from json_generator import *
import hashlib

import json
from kafka import KafkaProducer
from kafka.errors import KafkaError
import logging

from datetime import datetime, timezone

import blockchain_endpoints as blockchain

# from pqc.sign import falcon_512 as sigalg
# from pqc.sign import dilithium5 as sigalg

# from pqc.kem import kyber512 as kemalg
# from pqc.kem import kyber1024 as kemalg
# from pqc.kem import hqc_256 as kemalg
# from pqc.kem import mceliece348864 as kemalg

import struct

import sys

import time

import log_to_json as output_log

## better ecdsa

# ----------------------------------------------------------------
# Server configurations (PORT > 1024 doesn't require sudo access)
HOST = "147.102.37.120"
PORT = 6666

# ----------------------------------------------------------------
# Enable KAFKA bus for attestation results
# KAFKA = True
KAFKA = False

# ---------------------------------------------------
# KAFKA configuration settings
KAFKA_HOST = '10.160.3.213:9092'
KAFKA_TOPIC = 'attestation.evidence'
# ---------------------------------------------------

# ---------------------------------------------------
URL = "http://10.160.3.213:3001"
# ---------------------------------------------------

# Server Client secure connection files
cert_file = "ssl_includes/server.crt"
key_file = "ssl_includes/server.key"

# Default Messages
att_rqrt_message_service = "attestation_srvc"
att_rqrt_message_kernel = "attestation_krnl"

# ---------------------------------------------------
# Reference values for verification (don't share them with anyone!)

# ******** ALVEO U280 ******** 
# vrf_checksum_service = "9a6d1cc84adfa359fd617193c6625dc72ed73308f93522e7896511b5001bd5db"
# vrf_checksum_aes_krnl = "05401f5e49787579b3da4b7d977ad65fffeafbcac1019836ac191ed25e1e8791"

# ******** ZCU104 ******** 
# vrf_checksum_service = "2238fd5db327315074dcb913205893a80c6f2ce1fdf19d97f2fa2a1b29e4248c"
# vrf_checksum_aes_krnl = "64fb72c6b5ff3af9789e08cf3dfb71037ddb7d77c6f34fec16607510d8472e21"
# ************************ 



###### SHA3-512 (ALVEO) #######
# vrf_checksum_service = "9a6d1cc84adfa359fd617193c6625dc72ed73308f93522e7896511b5001bd5db15c45bdf8ca6b30c0d3a01aa6eb46f24b36c0ea5c794adf7941f4365a951608b"
# vrf_checksum_aes_krnl = "15c45bdf8ca6b30c0d3a01aa6eb46f24b36c0ea5c794adf7941f4365a951608bff2768d2d22f7888be132225e4f30a8f7a1f872ee81d30897de4c325ab601474"
# vrf_checksum = "a224995ea23bdd177db9061fcfac7b3fae84165f12cd800222caa3ea4671c52188cd153f310d8b6ee08e610d12bc78d284e2182139b75868214737fde475fc36"

###### SHA3-512 (MPSOC) #######
vrf_checksum_service = "9a6d1cc84adfa359fd617193c6625dc72ed73308f93522e7896511b5001bd5db15c45bdf8ca6b30c0d3a01aa6eb46f24b36c0ea5c794adf7941f4365a951608b"
vrf_checksum_aes_krnl = "0726c99ae6e0a291cb0327c8685640c2e1f47eac9f5a3accfc4a591fb9c017454c9f819d0f2dfd624f3b3ff73bf55f20ae0bfd5bf2f7f6206b911c8578152763"
vrf_checksum = "a224995ea23bdd177db9061fcfac7b3fae84165f12cd800222caa3ea4671c52188cd153f310d8b6ee08e610d12bc78d284e2182139b75868214737fde475fc36"


# ---------------------------------------------------
# vrf_checksum = "0cc0d9d7f2ff30dee5211804b561c7075ede7468a085d70dc50bfe2eb145960d" # correct

# vrf_checksum = "f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"  # Wrong



vrf_signature = "f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"

# bitstr_key = "privateer123"
bitstr_key = "a3f9b2e8c4d1a6b0e7f5c9d2a4b8f3e6c1d7a0b9e5f2c4d8a3b6e0f1c9d2a5b7"
# ---------------------------------------------------

# For development purposes
# puf_response = b"01100010010010110111010101001001111001000100110111110001010011100111011011101001010000101110000010110000101010110110011101010001"


# puf_response = "a3f9b2e8c4d1a6b0e7f5c9d2a4b8f3e6c1d7a0b9e5f2c4d8a3b6e0f1c9d2a5b7"
# puf_response = "00000001587e01c01c000080b7f8000000000001587e01c01c000080b7f80000"
puf_response = "00000001587e01c01c000080b7f8000000000001587e01c01c000080b7f80000"


# Large data transfer with socket
def receive_large_data_with_ssl(sock, kem_alg):
    # 1. Receive the size of the incoming data (4-byte unsigned integer)
    # data_size_bytes = sock.recv(4)  # Receive 4 bytes for the data size
    # if not data_size_bytes:
    #     raise ConnectionError("Failed to receive data size.")
    
    # data_size = struct.unpack('!I', data_size_bytes)[0]  # Unpack the 4-byte integer

    # kyber 1024

    match kem_alg:
        case "kyber":
            data_size = 1568
        case "mceliece":
            data_size = 261120
        case _:
            print("Invalid KEM name")

    print(f"Expecting {data_size} bytes of data.")

    # 2. Receive the actual data in chunks
    data = b''
    chunk_size = 15360  # 15K chunk size
    received_bytes = 0

    while received_bytes < data_size:
        chunk = sock.recv(min(chunk_size, data_size - received_bytes))
        if not chunk:
            raise ConnectionError("Connection lost while receiving data.")
        data += chunk
        received_bytes += len(chunk)

    print(f"Received {received_bytes} bytes of data.")
    return data

#####
# Function to extract r and s from a DER encoded signature
def der_decode_signature(encoded_signature):
    if encoded_signature[0] != 0x30:  # check if it is a sequence
        raise ValueError("Invalid DER encoding")
    
    # Skip the first byte and the length byte
    pos = 2
    
    # Read r
    if encoded_signature[pos] != 0x02:  # check if it is an integer
        raise ValueError("Invalid DER encoding for r")
    r_len = encoded_signature[pos + 1]
    r = int.from_bytes(encoded_signature[pos + 2: pos + 2 + r_len], 'big')
    pos += 2 + r_len
    
    # Read s
    if encoded_signature[pos] != 0x02:  # check if it is an integer
        raise ValueError("Invalid DER encoding for s")
    s_len = encoded_signature[pos + 1]
    s = int.from_bytes(encoded_signature[pos + 2: pos + 2 + s_len], 'big')
    
    return r, s

######
# Function to create DER encoded signature from r and s
def der_encode_signature(r, s):
    # Convert r and s to bytes
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, 'big')
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, 'big')

    # Create the DER encoding
    length = len(r_bytes) + len(s_bytes) + 4
    return b'\x30' + struct.pack('B', length) + \
           b'\x02' + struct.pack('B', len(r_bytes)) + r_bytes + \
           b'\x02' + struct.pack('B', len(s_bytes)) + s_bytes


# ----------------------------------------------------------------
def aes_decrypt_ecb(ciphertext, key):
    # Create an AES cipher object in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the ciphertext
    decrypted_data = cipher.decrypt(ciphertext)

    return decrypted_data


"""
def decrypt_aes_ecb_from_hex(ciphertext_hex, key_hex, original_plaintext_len_bytes):
    try:
        # 1. Convert hex strings to bytes
        key_bytes = unhexlify(key_hex)
        ciphertext_bytes = unhexlify(ciphertext_hex)

        # Validate key length (must be 16, 24, or 32 bytes for AES)
        if len(key_bytes) not in [16, 24, 32]:
            print(f"Error: Invalid key length. Key must be 16, 24, or 32 bytes (got {len(key_bytes)}).")
            return None

        # Validate ciphertext length (must be a multiple of AES block size - 16 bytes)
        if len(ciphertext_bytes) == 0:
            print("Error: Ciphertext cannot be empty.")
            return None
        if len(ciphertext_bytes) % AES.block_size != 0:
            print(f"Error: Ciphertext length ({len(ciphertext_bytes)} bytes) is not a multiple of AES block size ({AES.block_size} bytes).")
            return None
        
        # 2. Create an AES cipher object in ECB mode
        cipher = AES.new(key_bytes, AES.MODE_ECB)

        # 3. Decrypt the ciphertext
        decrypted_padded_bytes = cipher.decrypt(ciphertext_bytes)

        # 4. Handle "Unpadding" (Truncate to original length due to zero-padding on C++ side)
        if original_plaintext_len_bytes > len(decrypted_padded_bytes):
            print(f"Error: Original plaintext length ({original_plaintext_len_bytes} bytes) is greater than decrypted data length ({len(decrypted_padded_bytes)} bytes).")
            # This shouldn't happen if ciphertext was correctly formed from original_plaintext_len_bytes
            return hexlify(decrypted_padded_bytes).decode() # Return what we got, but it's an error state

        decrypted_final_bytes = decrypted_padded_bytes[:original_plaintext_len_bytes]

        # 5. Convert decrypted bytes back to a hex string for return
        decrypted_final_hex = hexlify(decrypted_final_bytes).decode()

        return decrypted_final_hex

    except ValueError as ve: # Catches errors from unhexlify if hex strings are malformed
        print(f"Error: Invalid hexadecimal string provided. {ve}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        return None
"""



# ----------------------------------------------------------------
def aes_decrypt_cbc(ciphertext, key):

    # IV should be a bytes object, convert hex string to bytes
    iv = bytes.fromhex("fedcba9876543210fedcba9876543210")
    # iv = bytes.fromhex("fedcba9876543210fedcba9876543211")

    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext
    decrypted_data = cipher.decrypt(ciphertext)

    return decrypted_data




def bytes_to_hex(byte_data):
    # Convert bytes to a hexadecimal string
    return binascii.hexlify(byte_data).decode('utf-8')

def hex_to_bytes(hex_string):
    # Convert hexadecimal string to bytes
    return binascii.unhexlify(hex_string.strip())
# ----------------------------------------------------------------


def bits_to_bytes(bit_string):
    # Split the bit string into groups of 8 (one byte)
    bytes_list = [bit_string[i:i+8] for i in range(0, len(bit_string), 8)]
    
    # Convert each group of 8 bits to a byte
    bytes_data = bytes([int(byte, 2) for byte in bytes_list])
    
    return bytes_data


from fastecdsa.curve import P256
from fastecdsa.keys import gen_keypair
from fastecdsa.point import Point
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Helper functions to convert public key to hex and back
def point_to_hex(point):
    """Converts an elliptic curve point to a hex string."""
    return point.x.to_bytes(32, 'big').hex() + point.y.to_bytes(32, 'big').hex()

def hex_to_point(hex_str, curve=P256):
    """Converts a hex string back to an elliptic curve point."""
    x = int(hex_str[:64], 16)
    y = int(hex_str[64:], 16)
    return Point(x, y, curve)

# AES encryption function
def aes_encrypt(plaintext, key, iv):
    """Encrypts plaintext using AES CBC mode with the provided key and IV."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext


# ---------------------------------------------------
# vrf_checksum_service = "2afe2f2a9bd500bba2e72e4a10d9cb4a49310dc06517a244cf66b598d74c49e6"
# vrf_checksum = "2afe2f2a9bd500bba2e72e4a10d9cb4a49310dc06517a244cf66b598d74c49e6"
# ---------------------------------------------------


# For reseting terminal text color
init(autoreset=True)

# Create a socket
# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

break_loop = False

# ---------------------------------------------------
# Auxiliary functions

def read_json_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)


def get_time():   
    # Get the current UTC time
    current_time = datetime.utcnow()
    # current_time = datetime.now(datetime.UTC)

    # Format time ('Z' indicates UTC)
    formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    return formatted_time


# ---------------------------------------------------
# Configure logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


# Create a producer with JSON serializer
if (KAFKA == True):
    producer = KafkaProducer(
        bootstrap_servers   = KAFKA_HOST,
        value_serializer    = lambda v: json.dumps(v).encode('utf-8')
    )

# Main program function
def main():
    # ----------------------------------------------------------------
    # Process CLI arguments to determine what cryptographic algorithms are going to be used
    # Possible Sign options: "ecdsa", "falcon", "dilithium"
    # Possible KEM options: "ecdh", "kyber", "mceliece"
    # ----------------------------------------------------------------
    print("Getting configuration parameters from CLI arguments...")
    sign_alg = sys.argv[1]
    kem_alg = sys.argv[2]

    match sign_alg:
        case "ecdsa":
            # from ecdsa import SigningKey, NIST256p, VerifyingKey
            from fastecdsa import curve, ecdsa, keys
            from fastecdsa.keys import export_key, import_key, gen_keypair
        case "falcon":
            # from pqc.sign import falcon_512 as sigalg
            from pqc.sign import falcon_1024 as sigalg
        case "dilithium":
            from pqc.sign import dilithium5 as sigalg
        case _:
            print("Invalid siganture algorithm")

    match kem_alg:
        case "ecdh":
            from fastecdsa.curve import P256
            from fastecdsa.keys import gen_keypair
            from fastecdsa.point import Point

        case "kyber":
            from pqc.kem import kyber1024 as kemalg
        case "mceliece":
            from pqc.kem import mceliece348864 as kemalg
        case _:
            print("Invalid KEM algorithm")

    print("-----------------------------------------------------------------")
    print("Selected: " + sign_alg + " + " + kem_alg)
    print("-----------------------------------------------------------------")


    try:
        # Keep the server connection open
        while True:
            # Create a socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # TODO: Check if this works
            # Use this to prevent "OSError: [Errno 98] Address already in use"
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind the socket to a specific address and port
            server_socket.bind((HOST, PORT))

            # Listen for incoming connections
            server_socket.listen()

            # Reset the attestation status for both the service and the kernel
            att_status = "fail"
            att_service_status = 0
            att_kernel_status = 0

            print("-----------------------------------------------------------------")
            print("Remote Attestation Server")
            print("Server listening on {} [Port: {}]".format(HOST, PORT))
            print("-----------------------------------------------------------------")

            # Accept a client connection
            client_socket, client_address = server_socket.accept()

            # Wrap the socket with SSL/TLS
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

            secure_client_socket = ssl_context.wrap_socket(
                client_socket, 
                server_side=True,
                do_handshake_on_connect=True,
            )

            # -----------------------------------------------------------------------------------
            # PART 1 - Verify attestation service 
            # -----------------------------------------------------------------------------------
            print("\n-----------------------------------------------------------------")
            print("EDGE NODE ATTESTATION SERVICE ATTESTATION")
            print("-----------------------------------------------------------------")
            
            # Generate attestation request with the nonce
            nonce = Crypto.Random.get_random_bytes(8)
            nonce_hex = nonce.hex()
            print("Nonce:", nonce_hex)
            att_request = att_rqrt_message_service + nonce_hex

            secure_client_socket.sendall(att_request.encode('utf-8'))

            # Receive from the client
            # data_received = secure_client_socket.recv(144)
            # data_received = secure_client_socket.recv(15360)
            data_received = secure_client_socket.recv(15360)
            # data_received = secure_client_socket.recv(2048)

            data_received_utf8 = data_received.decode('utf-8')
            timestamp_verify_service = get_time()

            # Extract the different variables from the attestation report
            parsed_received = {}

            # *** SHA256 ***
            # parsed_received['nonce'] = data_received_utf8[0:16]
            # parsed_received['checksum'] = data_received_utf8[16:80]
            # parsed_received['aes_checksum'] = data_received_utf8[80:144]
            # parsed_received['signature'] = data_received_utf8[144:]

            # *** SHA3-512 ***
            parsed_received['nonce']            = data_received_utf8[0  :16 ]
            parsed_received['checksum']         = data_received_utf8[16 :144]
            parsed_received['aes_checksum']     = data_received_utf8[144:272]
            parsed_received['signature']        = data_received_utf8[272:   ]

            # Print received attestation report
            print("-----------------------------------------------------------------")
            print("Received Attestation Report")
            print("Nonce                 : {}".format(parsed_received['nonce']))
            print("Att. Service Checksum : {}".format(parsed_received['checksum']))
            print("AES Kernel checksum   : {}".format(parsed_received['aes_checksum']))
            print("Signature             : {}".format(parsed_received['signature']))
            print("-----------------------------------------------------------------")
            print("Reference Values")
            print("Att. Service Checksum :", vrf_checksum_service)
            print("AES Kernel Checksum   :", vrf_checksum_aes_krnl)
            print("-----------------------------------------------------------------")
            print("Attestation result:")
            
            # FALCON signature verification

            # Read the FALCON public key for verification
            # with open("falcon_keys/public_key.pem", 'rb') as pub_file:
            # with open("dilithium_keys/public_key.pem", 'rb') as pub_file:
            #     loaded_pk = pub_file.read()


            # Load the respective key and verify the attestation report
            match sign_alg:
                case "ecdsa":
                    _, public_key = import_key("ecdsa_keys/public_key.pem")

                    # Decode the signature from DER format
                    
                    try:
                        signature_verification = True
                        r, s = der_decode_signature(bytes.fromhex(parsed_received['signature']))
                        valid = ecdsa.verify((r, s),  data_received_utf8[0:272].encode('utf-8'), public_key)
                    except:
                        signature_verification = False

                    # with open("ecdsa_keys/public_key.pem", 'rb') as priv_file:
                    #     loaded_pk = VerifyingKey.from_pem(priv_file.read())
                    # try:
                    #     signature_verification = True
                    #     loaded_pk.verify(bytes.fromhex(parsed_received['signature']), 
                    #         data_received_utf8[0:272].encode('utf-8'))
                    # except:
                    #     signature_verification = False

                    print(signature_verification)

                case "falcon":
                    # with open("falcon_keys/public_key.pem", 'rb') as priv_file:
                    with open("falcon_keys/public_key_f1024.pem", 'rb') as priv_file:
                        loaded_pk = priv_file.read()
                    try:
                        signature_verification = True
                        sigalg.verify(bytes.fromhex(parsed_received['signature']), 
                            data_received_utf8[0:272].encode('utf-8'), loaded_pk)
                    except:
                        signature_verification = False
            
                case "dilithium":
                    with open("dilithium_keys/public_key.pem", 'rb') as priv_file:
                        loaded_pk = priv_file.read()
                    try:
                        signature_verification = True
                        sigalg.verify(bytes.fromhex(parsed_received['signature']), 
                            data_received_utf8[0:272].encode('utf-8'), loaded_pk)
                    except:
                        signature_verification = False

                case _:
                    print("Invalid signature name")

            """
            try:
                falcon_verification = True
                sigalg.verify(bytes.fromhex(parsed_received['signature']), 
                    # data_received_utf8[0:144].encode('utf-8'), loaded_pk)
                    data_received_utf8[0:272].encode('utf-8'), loaded_pk)
            except:
                falcon_verification = False
            """ 

            # ---------------------------------------------------------------- #
            # ---------------------------------------------------------------- #
            # Save results to json
            log_entry = {
                "timestamp_unix": time.time(),
                "timestamp_readable": time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(time.time())),
                "client_address": str("FPGA-A"), # Assuming you have client_address
                "received_report": {
                    "nonce": parsed_received['nonce'],
                    "attestation_service_checksum": parsed_received['checksum'],
                    "aes_kernel_checksum": parsed_received['aes_checksum'],
                    "signature": "passed" if signature_verification else "failed",

                },
                "reference_values": {
                    "nonce": nonce_hex,
                    "attestation_service_checksum": vrf_checksum_service,
                    "aes_kernel_checksum": vrf_checksum_aes_krnl,
                },
            }

            # Define the path for your data file
            DATA_FILE_PATH = "attestation_service_report.json"

            # Save the combined log entry
            output_log.save_data_to_json_file(log_entry, DATA_FILE_PATH)
            # ---------------------------------------------------------------- #
            # ---------------------------------------------------------------- #






            # Check if we received the correct values
            if  (parsed_received['nonce'] != nonce_hex) or (parsed_received['checksum'] != vrf_checksum_service) or (parsed_received['aes_checksum'] != vrf_checksum_aes_krnl) or (signature_verification == False):
                print(f"{Fore.RED}\u2718 [HW ACCELERATOR ATTESTATION SERVICE] Attestation failed")
                print("-----------------------------------------------------------------")

                # Send message that the attestation failed
                att_status = "fail"
                att_service_status = 0
                secure_client_socket.sendall(att_status.encode('utf-8'))

            else:
                print(f"{Fore.GREEN}\u2713 [HW ACCELERATOR ATTESTATION SERVICE] Successful Attestation")
                print("-----------------------------------------------------------------")

                # Send message that the attestation completed successfully
                att_status = "pass"
                att_service_status = 1
                secure_client_socket.sendall(att_status.encode('utf-8'))


                # -----------------------------------------------------------------------------------
                # PART 2 - Verify FPGA kernel 
                # -----------------------------------------------------------------------------------
                print("\n-----------------------------------------------------------------")
                print("FPGA ACCELERATOR KERNEL ATTESTATION")
                print("-----------------------------------------------------------------")

                # Generate attestation request with the nonce
                nonce = Crypto.Random.get_random_bytes(8)
                nonce_hex = nonce.hex()
                print("Nonce:", nonce_hex)
                att_request = att_rqrt_message_kernel + nonce_hex

                secure_client_socket.sendall(att_request.encode('utf-8'))

                # Receive from the client
                # data_received = secure_client_socket.recv(288)
                # data_received = secure_client_socket.recv(2048) # Working for falcon
                data_received = secure_client_socket.recv(15360) # increased buffer size for dilithium signature



                # ------------------------------------------------------------ #
                # ------------------------------------------------------------ #
                # PUF Responses for demo
                puf_hd_list_req = "puf_hd_list"
                secure_client_socket.sendall(puf_hd_list_req.encode('utf-8'))
                data_received_puf_hd_list = secure_client_socket.recv(128)
                print("PUF HD LIST : {}".format(data_received_puf_hd_list))
                # ------------------------------------------------------------ #
                # ------------------------------------------------------------ #


                # data_received = secure_client_socket.recv(144) # WORKING
                # data_received_utf8 = data_received.decode('utf-8')
                # data_received_bytes = binascii.unhexlify(data_received_utf8)
                timestamp_verify_kernel = get_time()

                # -----------------------------------------------------------------------------------
                # Decrypt received attestation report (WORKING)
                # decipher = AES.new(bits_to_bytes(puf_response), AES.MODE_ECB)
                # data_received_utf8_dec = decipher.decrypt(data_received).decode('utf-8')
                # -----------------------------------------------------------------------------------

                # -----------------------------------------------------------------------------------
                # NEW DECRYPTION FOR HARDWARE AES

                # test = "5c11810e7b985b6dcd923c8567ed17c4dead57fb31cb0e244e3d5b9e00634e7f51fdaeaa723f640b569bd1cbf87a8e2880ab630c89f150cf185740ea3538bfb846370640bfddd5716e4f4cb0dc44756a0eacc71e8e9f426caee910cf61982ef57d16b53fcc7efbf185ef00046a5b7f0c08ed5357782740a9febe8a204ce6fca708ed5357782740a9febe8a204ce6fca7"
                # print("###########")
                # print(data_received.decode('utf-8'))
                # print("###########")

                attestation_report_utf8 = data_received.decode('utf-8')

                print("### ATTESTATION REPORT")
                # print(attestation_report_utf8)
                print("###")

                key = hex_to_bytes(puf_response)
                attestation_report_utf8_strip = attestation_report_utf8.strip().replace(' ', '')
                ciphertext = binascii.unhexlify(attestation_report_utf8_strip)

                # decrypted_data = aes_decrypt_ecb(ciphertext[:80], key) # sha256

                print("#"*50)
                print(" [PUF KEY] >>>> {}".format(key.hex()))
                print("#"*50)

                decrypted_data = aes_decrypt_ecb(ciphertext[:144], key) # WORKING


                # ------------------------------------------------------------ #
                # ------------------------------------------------------------ #
                # ------------------------------------------------------------ #
                # ------------------------------------------------------------ #
                # ------------------------------------------------------------ #
                # original_input_len_bytes = len(ciphertext[:144]) // 2
                # decrypted_data = decrypt_aes_ecb_from_hex(ciphertext[:144], key, original_input_len_bytes)
                # print(">>>>>>>>>>>>>>>> {}".format(decrypted_data))
                # ------------------------------------------------------------ #
                # ------------------------------------------------------------ #
                # ------------------------------------------------------------ #
                # ------------------------------------------------------------ #
                # ------------------------------------------------------------ #




                # decrypted_data = aes_decrypt_cbc(ciphertext[:144], key) ######### Latest


                data_received_utf8_dec = bytes_to_hex(decrypted_data)
                # data_received_utf8_dec = decrypted_data


                print("#"*50)
                # print("[DECRYPTED ATT. REPORT] >>>> {}".format(decrypted_data.hex()))
                print("[DECRYPTED ATT. REPORT] >>>> {}".format(decrypted_data))
                print("#"*50)

                # -----------------------------------------------------------------------------------
                
                # Extract the different variables from the attestation report
                parsed_received = {}

                # parsed_received['nonce'] = data_received_utf8_dec[0:16]
                # parsed_received['checksum'] = data_received_utf8_dec[16:80]
                # parsed_received['signature'] = attestation_report_utf8[288:]

                parsed_received['nonce']        = data_received_utf8_dec[0:16]
                parsed_received['checksum']     = data_received_utf8_dec[16:144]
                parsed_received['signature']    = attestation_report_utf8[160:]


                # try:
                #     falcon_verification = True
                #     sigalg.verify(bytes.fromhex(parsed_received['signature']), 
                #         attestation_report_utf8[0:288+256].encode('utf-8'), loaded_pk)
                # except:
                #     falcon_verification = False

                # Load the respective key and verify the attestation report
                match sign_alg:
                    case "ecdsa":
                        # try:
                        #     signature_verification = True
                        #     loaded_pk.verify(bytes.fromhex(parsed_received['signature']), 
                        #         attestation_report_utf8[0:288+256].encode('utf-8'))
                        # except:
                        #     signature_verification = False

                        # _, public_key = import_key("ecdsa_keys/public_key.pem")

                        # Decode the signature from DER format
                        
                        try:
                            signature_verification = True

                            ############################################
                            print("="*60)
                            print("[SIGNATURE] >>>>>>>>>> {}".format(parsed_received['signature']))
                            print("-"*60)
                            print("[REPORT] >>>>>>>>>> {}".format(data_received_utf8_dec[0:144]))
                            print("="*60)

                            ############################################

                            r, s = der_decode_signature(bytes.fromhex(parsed_received['signature']))
                            # valid = ecdsa.verify((r, s),  attestation_report_utf8[0:288+256].encode('utf-8'), public_key)
                            valid = ecdsa.verify((r, s),  attestation_report_utf8[0:144].encode('utf-8'), public_key)
                            print(valid)
                        except:
                            signature_verification = False

                    case "falcon" | "dilithium": 
                        try:
                            signature_verification = True
                            sigalg.verify(bytes.fromhex(parsed_received['signature']), 
                                attestation_report_utf8[0:288+256].encode('utf-8'), loaded_pk)
                        except:
                            signature_verification = False

                    case _:
                        print("Invalid signature name")

                # print(falcon_verification)

                # Print received attestation report
                print("-----------------------------------------------------------------")
                print("Received Attestation Report")
                print("Nonce                 : {}".format(parsed_received['nonce']))
                print("Kernel Checksum       : {}".format(parsed_received['checksum']))
                print("Signature             : {}".format(parsed_received['signature']))
                print("-----------------------------------------------------------------")
                print("Reference Values")
                print("Kernel Checksum       :", vrf_checksum)
                # print("Certificate :", vrf_signature)
                print("-----------------------------------------------------------------")
                print("Attestation result:")



                puf_resp = "123"
                puf_response_ref = "123"

                # ---------------------------------------------------------------- #
                # ---------------------------------------------------------------- #
                # Save results to json
                log_entry = {
                    "timestamp_unix": time.time(),
                    "timestamp_readable": time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(time.time())),
                    "client_address": str("FPGA-A"), # Assuming you have client_address
                    "received_report": {
                        "nonce": parsed_received['nonce'],
                        "user_kernel_checksum": parsed_received['checksum'],
                        "signature": "passed" if signature_verification else "failed",
                        "puf_response": puf_response,
                        "puf_hd_list": data_received_puf_hd_list.decode('utf-8')
                    },
                    "reference_values": {
                        "nonce": nonce_hex,
                        "user_kernel_checksum": vrf_checksum,
                        "puf_response": puf_response
                    },
                }

                # Define the path for your data file
                DATA_FILE_PATH = "user_kernel_report.json"

                # Save the combined log entry
                output_log.save_data_to_json_file(log_entry, DATA_FILE_PATH)
                # ---------------------------------------------------------------- #
                # ---------------------------------------------------------------- #






                # Check if we received the correct values
                if (parsed_received['nonce'] != nonce_hex) or (parsed_received['checksum'] != vrf_checksum or (signature_verification == False)):
                # if (parsed_received['nonce'] != nonce_hex) or (parsed_received['checksum'] != vrf_checksum):
                    print(f"{Fore.RED}\u2718 [FPGA BITSTREAM] Attestation failed")
                    print("-----------------------------------------------------------------")

                    # Send message that the attestation failed
                    att_status = "fail"
                    att_kernel_status = 0
                    secure_client_socket.sendall(att_status.encode('utf-8'))

                    # Default Values 


                else:
                    print(f"{Fore.GREEN}\u2713 [FPGA BITSTREAM] Successful Attestation")

                    # Send message that the attestation completed successfully
                    att_status = "pass"
                    att_kernel_status = 1
                    secure_client_socket.sendall(att_status.encode('utf-8'))

                    # Receive the key request 
                    data_received = secure_client_socket.recv(128)
                    data_received_utf8 = data_received.decode('utf-8')      

                    # Send the bitstream decryption key
                    if data_received_utf8 == "bitstr_key":
                        print("-----------------------------------------------------------------")                    
                        print("Sending the bitstream decryption key...")
                        
                        """
                        server_ecdh = DiffieHellman()

                        # Exchange public keys with the client
                        public_key_hex = get_key_hex(server_ecdh.public_key)
                        secure_client_socket.sendall(public_key_hex.encode('utf-8'))
                        public_key_received = secure_client_socket.recv(1024)
                        public_key_received_utf8 = public_key_received.decode('utf-8')
                        public_key_received_bytes = bytes.fromhex(public_key_received_utf8)
                        public_key_received_object = get_key_object(public_key_received_bytes)

                        # Complete the key exchange
                        bitstr_key_enc_ecdh = server_ecdh.encrypt(public_key_received_object, bitstr_key)
                        bitstr_key_enc_ecdh_hex = bitstr_key_enc_ecdh.hex()
                        secure_client_socket.sendall(bitstr_key_enc_ecdh_hex.encode('utf-8'))
                        print("Key Derivation Completed")
                        """

                        # Apply the respective KEM algorithm
                        match kem_alg:
                            case "ecdh":
                                """
                                server_ecdh = DiffieHellman()

                                # Exchange public keys with the client
                                public_key_hex = get_key_hex(server_ecdh.public_key)
                                secure_client_socket.sendall(public_key_hex.encode('utf-8'))
                                public_key_received = secure_client_socket.recv(1024)
                                public_key_received_utf8 = public_key_received.decode('utf-8')
                                public_key_received_bytes = bytes.fromhex(public_key_received_utf8)
                                public_key_received_object = get_key_object(public_key_received_bytes)

                                # Complete the key exchange
                                bitstr_key_enc_ecdh = server_ecdh.encrypt(public_key_received_object, bitstr_key)
                                bitstr_key_enc_ecdh_hex = bitstr_key_enc_ecdh.hex()
                                secure_client_socket.sendall(bitstr_key_enc_ecdh_hex.encode('utf-8'))
                                """

                                # Lets try a faster algorithm
                                server_private_key, server_public_key = gen_keypair(P256)
                                
                                public_key_hex = point_to_hex(server_public_key)
                                secure_client_socket.sendall(public_key_hex.encode('utf-8'))

                                public_key_received = secure_client_socket.recv(1024)
                                public_key_received_utf8 = public_key_received.decode('utf-8')
                                public_key_received_object = hex_to_point(public_key_received_utf8)

                                shared_secret_point = public_key_received_object * server_private_key
                                shared_secret = shared_secret_point.x.to_bytes(32, 'big')  

                                iv = os.urandom(16) 
                                encrypted_bitstr_key = aes_encrypt(bitstr_key.encode('utf-8'), shared_secret[:16], iv) 

                                # Step 6: Send the encrypted bitstr_key and IV to the client
                                secure_client_socket.sendall(encrypted_bitstr_key.hex().encode('utf-8'))  
                                secure_client_socket.sendall(iv)  
                                
                            case "kyber" | "mceliece":
                                # Receive Public Key from Client

                                # For large public key size, use custom transfer function
                                public_key_received = receive_large_data_with_ssl(secure_client_socket, kem_alg)

                                # Create a shared secret using the public key
                                ss, key_server = kemalg.encap(public_key_received)

                                # Send the generated ciphertext to the client
                                secure_client_socket.sendall(key_server)    # Send as bytes, no encoding

                                # Prepare to encrypt a message
                                key_server_bytes = ss[:32]                  # Use the first 32 bytes for AES-256

                                # Generate a random IV for AES
                                iv = os.urandom(AES.block_size)

                                # Create AES cipher
                                cipher = AES.new(key_server_bytes, AES.MODE_CBC, iv)

                                # Encrypt the message
                                ct_bytes = cipher.encrypt(pad(binascii.unhexlify(bitstr_key), AES.block_size))

                                # Send IV and ciphertext to the client
                                secure_client_socket.sendall(iv + ct_bytes)  # Send IV + ciphertext
                            case _:
                                print("Invalid KEM name")


                        """
                        # Kyber KEM

                        # Receive Public Key from Client
                        # public_key_received = secure_client_socket.recv(2048)
                        # public_key_received = secure_client_socket.recv(12984)

                        # For large public key size, use custom transfer function
                        public_key_received = receive_large_data_with_ssl(secure_client_socket)

                        print("test1")

                        # Create a shared secret using the public key
                        ss, key_server = kemalg.encap(public_key_received)

                        # Send the generated ciphertext to the client
                        secure_client_socket.sendall(key_server)    # Send as bytes, no encoding

                        # Prepare to encrypt a message
                        key_server_bytes = ss[:32]                  # Use the first 32 bytes for AES-256

                        print("AES")

                        # Generate a random IV for AES
                        iv = os.urandom(AES.block_size)

                        # Create AES cipher
                        cipher = AES.new(key_server_bytes, AES.MODE_CBC, iv)

                        # Encrypt the message
                        ct_bytes = cipher.encrypt(pad(binascii.unhexlify(bitstr_key), AES.block_size))


                        print("#####")
                        print(public_key_received[:128].hex())
                        print("#####")
                        print(key_server_bytes.hex())
                        print("#####")
                        print(iv.hex())
                        print("#####")
                        print(ct_bytes.hex())
                        print("#####")


                        # Send IV and ciphertext to the client
                        secure_client_socket.sendall(iv + ct_bytes)  # Send IV + ciphertext
                        """
                        

                        print("Message sent securely.")


                    else:
                        print("[Error] Unable to send the bitstream decryption key")



            # -------------------------------------------------------------------------------------
            start_time = time.time()
            print("\n-----------------------------------------------------------------")
            print("GENERATING JSON ATTESTATION REPORT")
            print("-----------------------------------------------------------------")        

            # First generate the Json for the edge server attestation 
            edge_server_id              = "Edge-Server-0-UC2"
            # fpga_id                     = "fpga-attestation-demo6"
            fpga_id                     = "fpga-UC2-00001"

            print("FPGA ID      : " + fpga_id)

            # att_service_claim           = "edge_accelerator_att_server"
            att_service_claim           = "edge_accelerator_att_service"
            att_service_timestamp       = timestamp_verify_service
            att_service_appraisal       = att_service_status

            kernel_claim                = "edge_accelerator_kernel"
            kernel_type                 = 2
            kernel_timestamp            = timestamp_verify_kernel
            kernel_appraisal            = att_kernel_status
            
            puf_claim                   = "edge_accelerator_puf_verification"

            att_report_json = generate_att_report_json(
                edge_server_id,
                fpga_id, 
                # ------------------------------
                att_service_claim,
                att_service_timestamp,
                att_service_appraisal,
                # ------------------------------
                kernel_claim,
                kernel_type,
                kernel_timestamp,
                kernel_appraisal,
                # ------------------------------
                puf_claim,
                att_service_timestamp,
                "1",
                ""
            )

            # -------------------------------------------------------------------------------------
            """
            # Generate private and public keys for signing the attestation report (NIST256p)
            private_key = SigningKey.generate(curve=NIST256p) 
            public_key = private_key.get_verifying_key()

            # Save keys to file
            with open("priv_key.pem", "wb") as f:
                f.write(private_key.to_pem(format="pkcs8"))

            with open("pub_key.pem", "wb") as f:
                f.write(public_key.to_pem())
            """

            # -------------------------------------------------------------------------------------
            # Instead of generating new keys, read them from a file
            
            # print("$$$")
            # public_key = private_key.get_verifying_key()
            # print(public_key.to_string().hex())

            # -------------------------------------------------------------------------------------
            # Calculate the checksum of the (Nonce + attestation report)
            att_report_json_str = json.dumps(att_report_json, sort_keys=True)
            concat_data = str(parsed_received['nonce']) +  att_report_json_str
            # json_checksum = hashlib.sha256(concat_data.encode('utf-8')).digest()
            json_checksum = hashlib.sha3_512(concat_data.encode('utf-8')).digest()
            # json_checksum = hashlib.sha256(concat_data.encode()).hexdigest()

            print("$$$$$$$$$$")
            print(json_checksum)
            print("$$$$$$$$$$")

            # Sign the hashed message

            match sign_alg:
                case "ecdsa":
                    # with open("blockchain_keys/private_key_ecdsa.pem") as f:
                    #     private_key = SigningKey.from_pem(f.read())
                    # json_signature = private_key.sign(json_checksum)
                    
                    private_key, public_key = import_key("blockchain_keys/private_key_ecdsa.pem")
                    r,s = ecdsa.sign(json_checksum, private_key)
                    json_signature = der_encode_signature(r,s)

                case "falcon":
                    with open("blockchain_keys/private_key_f1024.pem", 'rb') as priv_file:
                        loaded_sk = priv_file.read()
                    json_signature = sigalg.sign(json_checksum, loaded_sk)
                case "dilithium":
                    with open("blockchain_keys/private_key_d5.pem", 'rb') as priv_file:
                        loaded_sk = priv_file.read()
                    # json_signature = sigalg.sign(json_checksum.encode('utf-8'), loaded_sk)
                    json_signature = sigalg.sign(json_checksum, loaded_sk)
                case _:
                    print("Invalid signature name")

            # -------------------------------------------------------------------------------------
            # Then generate the Json for the final attestation server evidence
            att_evidence_timestamp      = get_time()
            att_evidence_nonce          = parsed_received['nonce']
            att_evidence_signature_type = "ECDSA-SHA256"
            # att_evidence_signature_type = "FALCON"
            att_evidence_signature      = json_signature.hex()  
            att_evidence_keyref         = "ecdsa_public_key_71"

            att_server_evidence_json = generate_att_server_evidence_json(
                att_evidence_timestamp, 
                att_evidence_nonce, 
                att_evidence_signature_type,
                att_evidence_signature, 
                att_evidence_keyref
            )

            # Combine the two generated json structures for the final attestation report
            json_combined = json.dumps({
                "EdgeAcceleratorReports": att_report_json,
                "AttestationServerEvidence": att_server_evidence_json
            })

            # print("Generated json structure:")
            # print(json_combined)

            # -------------------------------------------------------------------------------------
            # Upload the attestation results to the blockchain through KAFKA        
            """
            future = producer.send(KAFKA_TOPIC, json_combined)

            try:
                record_metadata = future.get(timeout=10)
                # Successful result returns assigned partition and offset
                print("[debug] topic : " + record_metadata.topic)
                print("[debug] partition : " + str(record_metadata.partition))
                print("[debug] offset : " + str(record_metadata.offset))

            except KafkaError as e:
                log.exception("[kafka] Error sending message")
                pass

            producer.flush()
            producer.close()
            """
            
            # -------------------------------------------------------------------------------------
            # PUSH DATA TO BLOCKCHAIN
            # -------------------------------------------------------------------------------------
            """
            print("\n-----------------------------------------------------------------")
            print("PUSHING ATTESTATION REPORT TO BLOCKCHAIN")
            print("-----------------------------------------------------------------")

            # Obtain JWT token that will be used for uploading data to the Blockchain
            jwt_token = blockchain.obtain_jwt_token(URL)
            print("Acquired JWT Token: {}".format(jwt_token))

            # print("Done.")

            # start_time = time.time()
            # Upload the attestation report json structure
            blockchain.push_data(json_combined, URL, jwt_token)
            print("Done pushing attestation report to the Blockchain.")
            print("Execution time: {:.2f} sec".format(time.time() - start_time))
            print("")


            with open("data/log_blockchain_{}.csv".format(sign_alg), "a") as myfile:
                myfile.write("{:.2f}\n".format(time.time() - start_time))
            """


            # -------------------------------------------------------------------------------------
            # PUSH DATA TO BLOCKCHAIN & CREATE JSON FILES
            # -------------------------------------------------------------------------------------
            print("\n-----------------------------------------------------------------")
            print("PUSHING ATTESTATION REPORT TO BLOCKCHAIN")
            print("-----------------------------------------------------------------")

            # Obtain JWT token that will be used for uploading data to the Blockchain
            jwt_token = blockchain.obtain_jwt_token(URL)
            print("Acquired JWT Token: {}".format(jwt_token))

            # Upload attestation JSON to blockchain
            start_time = time.time()
            blockchain.push_data(json_combined, URL, jwt_token)
            print("Done pushing attestation report to the Blockchain.")
            print("Execution time: {:.2f} sec".format(time.time() - start_time))
            print("")

            # Log upload time
            with open("data/log_blockchain_{}.csv".format(sign_alg), "a") as myfile:
                myfile.write("{:.2f}\n".format(time.time() - start_time))


            # -------------------------------------------------------------------------------------
            # SAVE A LOCAL COPY OF THE JSON INTO blockchain_history/
            # -------------------------------------------------------------------------------------
            # Ensure folder exists
            history_dir = "blockchain_history"
            os.makedirs(history_dir, exist_ok=True)

            # Create safe timestamp-based filename
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"evidence_{timestamp}.json"
            filepath = os.path.join(history_dir, filename)

            # --- FIX: ensure json_combined is saved as dict, not as escaped string ---
            # If json_combined is a JSON string, convert it back to dict first
            if isinstance(json_combined, str):
                try:
                    json_data = json.loads(json_combined)    # convert string → dict
                except json.JSONDecodeError:
                    json_data = {"error": "Invalid JSON string", "raw": json_combined}
            else:
                json_data = json_combined                   # already a dict

            # Save PRETTY JSON
            with open(filepath, "w") as f:
                json.dump(json_data, f, indent=4)
            print("-----------------------------------------------------------------\n")


            # -------------------------------------------------------------------------------------
            # Condition to break infinite loop
            if (break_loop == True):
                break

    except KeyboardInterrupt:
        print("Server terminated by user.")

    finally:
        print("Exiting...")
        print("-----------------------------------------------------------------") 
        server_socket.close()


if __name__ == "__main__":
    main()