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
import binascii

from json_generator import *
import hashlib

import json
from kafka import KafkaProducer
from kafka.errors import KafkaError
import logging

from datetime import datetime, timezone

import blockchain_endpoints as blockchain

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
vrf_checksum_service = "13572be371a8689a90ad3b9ba17f9b8396484afb5908bd0792027556d1a9ad3b"
vrf_checksum_aes_krnl = "05401f5e49787579b3da4b7d977ad65fffeafbcac1019836ac191ed25e1e8791"

# ---------------------------------------------------
vrf_checksum = "0cc0d9d7f2ff30dee5211804b561c7075ede7468a085d70dc50bfe2eb145960d" # correct
# vrf_checksum = "f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"  # Wrong
vrf_signature = "f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"
bitstr_key = "a3f9b2e8c4d1a6b0e7f5c9d2a4b8f3e6c1d7a0b9e5f2c4d8a3b6e0f1c9d2a5b7"
# ---------------------------------------------------

# For development purposes
puf_response = "a3f9b2e8c4d1a6b0e7f5c9d2a4b8f3e6c1d7a0b9e5f2c4d8a3b6e0f1c9d2a5b7"



# ----------------------------------------------------------------
def aes_decrypt_ecb(ciphertext, key):
    # Create an AES cipher object in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

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



# For reseting terminal text color
init(autoreset=True)

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
        # data_received = secure_client_socket.recv(96)
        data_received = secure_client_socket.recv(144)
        data_received_utf8 = data_received.decode('utf-8')
        timestamp_verify_service = get_time()

        # Extract the different variables from the attestation report
        parsed_received = {}

        parsed_received['nonce'] = data_received_utf8[0:16]
        parsed_received['checksum'] = data_received_utf8[16:80]
        parsed_received['aes_checksum'] = data_received_utf8[80:144]

        # Print received attestation report
        print("-----------------------------------------------------------------")
        print("Received Attestation Report")
        print("Nonce                 : {}".format(parsed_received['nonce']))
        print("Att. Service Checksum : {}".format(parsed_received['checksum']))
        print("AES Kernel checksum   : {}".format(parsed_received['aes_checksum']))
        print("-----------------------------------------------------------------")
        print("Reference Values")
        print("Att. Service Checksum :", vrf_checksum_service)
        print("AES Kernel Checksum   :", vrf_checksum_aes_krnl)
        print("-----------------------------------------------------------------")
        print("Attestation result:")

        # Check if we received the correct values
        if (parsed_received['nonce'] != nonce_hex) or (parsed_received['checksum'] != vrf_checksum_service) or (parsed_received['aes_checksum'] != vrf_checksum_aes_krnl):
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
            data_received = secure_client_socket.recv(288)
            timestamp_verify_kernel = get_time()


            attestation_report_utf8 = data_received.decode('utf-8')

            key = hex_to_bytes(puf_response)
            attestation_report_utf8 = attestation_report_utf8.strip().replace(' ', '')
            ciphertext = binascii.unhexlify(attestation_report_utf8)
            decrypted_data = aes_decrypt_ecb(ciphertext, key)
            data_received_utf8_dec = bytes_to_hex(decrypted_data)

            # -----------------------------------------------------------------------------------
            
            # Extract the different variables from the attestation report
            parsed_received = {}

            parsed_received['nonce'] = data_received_utf8_dec[0:16]
            parsed_received['checksum'] = data_received_utf8_dec[16:80]
            parsed_received['certificate'] = data_received_utf8_dec[80:144]

            # Print received attestation report
            print("-----------------------------------------------------------------")
            print("Received Attestation Report")
            print("Nonce                 : {}".format(parsed_received['nonce']))
            print("Kernel Checksum       : {}".format(parsed_received['checksum']))
            print("-----------------------------------------------------------------")
            print("Reference Values")
            print("Kernel Checksum       :", vrf_checksum)
            print("-----------------------------------------------------------------")
            print("Attestation result:")

            # Check if we received the correct values
            if (parsed_received['nonce'] != nonce_hex) or (parsed_received['checksum'] != vrf_checksum):
                print(f"{Fore.RED}\u2718 [FPGA BITSTREAM] Attestation failed")
                print("-----------------------------------------------------------------")

                # Send message that the attestation failed
                att_status = "fail"
                att_kernel_status = 0
                secure_client_socket.sendall(att_status.encode('utf-8'))

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
                    # Exchange the key using DH
                    print("-----------------------------------------------------------------")
                    print("Generating shared secret with ECDH")
                    print("Sending the bitstream decryption key...")
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

                else:
                    print("[Error] Unable to send the bitstream decryption key")


        # -------------------------------------------------------------------------------------
        print("\n-----------------------------------------------------------------")
        print("GENERATING JSON ATTESTATION REPORT")
        print("-----------------------------------------------------------------")        

        # First generate the Json for the edge server attestation 
        edge_server_id              = "Edge-Server-1"
        fpga_id                     = "fpga-attestation-demo6"

        print("FPGA ID      : " + fpga_id)

        # att_service_claim           = "edge_accelerator_att_server"
        att_service_claim           = "edge_accelerator_att_service"
        att_service_timestamp       = timestamp_verify_service
        att_service_appraisal       = att_service_status

        kernel_claim                = "edge_accelerator_kernel"
        kernel_type                 = 0
        kernel_timestamp            = timestamp_verify_kernel
        kernel_appraisal            = att_kernel_status

        att_report_json = generate_att_report_json(
            edge_server_id,
            fpga_id, 
            att_service_claim,
            att_service_timestamp,
            att_service_appraisal,
            kernel_claim,
            kernel_type,
            kernel_timestamp,
            kernel_appraisal
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
        with open("priv_key.pem") as f:
            private_key = SigningKey.from_pem(f.read())

        with open("pub_key.pem") as f:
            public_key = VerifyingKey.from_pem(f.read())
        

        # -------------------------------------------------------------------------------------
        # Calculate the checksum of the (Nonce + attestation report)
        att_report_json_str = json.dumps(att_report_json, sort_keys=True)
        concat_data = str(parsed_received['nonce']) +  att_report_json_str
        json_checksum = hashlib.sha256(concat_data.encode('utf-8')).digest()


        # Sign the hashed message
        json_signature = private_key.sign(json_checksum)

        # -------------------------------------------------------------------------------------
        # Then generate the Json for the final attestation server evidence
        att_evidence_timestamp      = get_time()
        att_evidence_nonce          = parsed_received['nonce']
        att_evidence_signature_type = "ECDSA-SHA256"
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

        print("Generated json structure:")
        print(json_combined)

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
        print("\n-----------------------------------------------------------------")
        print("PUSHING ATTESTATION REPORT TO BLOCKCHAIN")
        print("-----------------------------------------------------------------")

        # Obtain JWT token that will be used for uploading data to the Blockchain
        jwt_token = blockchain.obtain_jwt_token(URL)
        print("Acquired JWT Token: {}".format(jwt_token))

        # print("Done.")

        # Upload the attestation report json structure
        blockchain.push_data(json_combined, URL, jwt_token)
        print("Done pushing attestation report to the Blockchain.")
        print("")

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
