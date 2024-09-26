# ---------------------------------------------------
# Example for Client w/ socket SSL communication 
# ---------------------------------------------------
# Creator   : Ilias Papalamprou
# Date      : 12/2023
# ---------------------------------------------------
import socket
import ssl
import subprocess
from file_checksum import calculate_sha256_checksum
from ecdh import DiffieHellman, get_key_hex, get_key_object
from colorama import Fore, init
import binascii
import time
# For performing the AES encyrption on FPGA
import krnl_aes_encrypt

# Define if we want executed commands to show output
# DEBUG = True
DEBUG = False

# Server configurations
HOST = '147.102.37.120'
PORT = 6666

# Server Client secure connection files
cert_file = 'ssl_includes/client.crt'
key_file = 'ssl_includes/client.key'

# Default Messages
att_request_service = "attestation_srvc"
att_request_kernel = "attestation_krnl"

# For development
puf_response = "a3f9b2e8c4d1a6b0e7f5c9d2a4b8f3e6c1d7a0b9e5f2c4d8a3b6e0f1c9d2a5b7"

def bits_to_bytes(bit_string):
    # Split the bit string into groups of 8 (one byte)
    bytes_list = [bit_string[i:i+8] for i in range(0, len(bit_string), 8)]
    
    # Convert each group of 8 bits to a byte
    bytes_data = bytes([int(byte, 2) for byte in bytes_list])
    
    return bytes_data


# Accelerator kernel files
xclbin_file = "demo_kernels/enc.xclbin"
xclbin_output_file = "demo_kernels/decrypted.xclbin"


# For reseting terminal text color
init(autoreset=True)

# Auxiliary functions to extract command output data
def extract_first_element(line):
    # Split the line by space and return the first element
    elements = line.split()
    return elements[0] if elements else None


# Caclulate values required for the remote attestation service verification
def attestation_service(nonce, input_file):
    # Calculate checksum of attestation service
    file_checksum = calculate_sha256_checksum(input_file)

    aes_kernel_checksum = calculate_sha256_checksum("krnl_aes_test_hw.xclbin")

    # Generate attestation report
    attestation_report = nonce + file_checksum + aes_kernel_checksum

    print("Att. Service Checksum : {}".format(file_checksum))
    print("AES Kernel checksum   : {}".format(aes_kernel_checksum))
    
    return attestation_report


# Calculate values required for the remote attestation of the accelearted kernel
def attestation_accelerated_kernel(nonce, input_file):
    # Extract bitstream from the xclbin application into a seperate file
    file_checksum = calculate_sha256_checksum(xclbin_file)

    # Generate attestation report including the received nonce
    attestation_report = nonce + file_checksum


    # Encrypt attestation report in the FPGA
    encrypted_attestation_report = krnl_aes_encrypt.aes_encrypt_kernel(puf_response, attestation_report)

    # print(encrypted_attestation_report)

    return encrypted_attestation_report


# Bitstream decryption function
def bitstream_decryption(input_file, output_file, bitstr_key):
    # Decrypt the bitstream file using OpenSSL and AES algorithm, with the received key after a successful attestation
    print("Decrypting bitstream...")
    try:
        cmd_log = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-in", input_file, "-out", output_file, "-k", bitstr_key, "-pbkdf2"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if DEBUG : print(cmd_log.stdout.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        print("OPENSSL Decryption Error")
        print(e.stderr.decode('utf-8'))

    # Remove the raw bitstream files
    print("Done.")
    print("-----------------------------------------------------------------")


# Main program function
def main():
    # Start timer
    start_time = time.time()

    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    try:
        client_socket.connect((HOST, PORT))

    # Print an error if the connection was unsuccessful
    except Exception as e:
        print("[Client] Connection error: {}".format(e))
        return

    # Wrap the socket with SSL/TLS
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Disabling hostname verification
    ssl_context.check_hostname = False  

    # Disabling certificate verification
    ssl_context.verify_mode = ssl.CERT_NONE  

    # Load client certificate and private key
    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    secure_client_socket = ssl_context.wrap_socket(client_socket, server_hostname=HOST)

    print("-----------------------------------------------------------------")
    print("Edge Accelerator connected to {} [Port: {}]".format(HOST, PORT))
    print("-----------------------------------------------------------------")

    # Receive and print the response from the server
    data_received = secure_client_socket.recv(1024)
    data_received_utf8 = data_received.decode('utf-8')


    # Perform remote attestation procedure if the correct request is received [att_rsqt + nonce]
    if (data_received_utf8[0:16] == att_request_service):
        print("\n-----------------------------------------------------------------")
        print("VERIFYING ATTESTATION INFRASTRUCTURE")
        print("-----------------------------------------------------------------")

        # Get the nonce value
        nonce = data_received_utf8[16:32]
        print("Received Nonce:", nonce)

        attestation_report = attestation_service(nonce, "client_socket_ssl.py")

        # Send attestation report to the verification server
        print("-----------------------------------------------------------------")
        print("Sending Attestation report to the Verification Server...")
        print(attestation_report)
        secure_client_socket.sendall(attestation_report.encode('utf-8'))
        print("-----------------------------------------------------------------")
        print("Waiting for response...")

        data_received = secure_client_socket.recv(1024)
        data_received_utf8 = data_received.decode('utf-8')

        if (data_received_utf8 == "fail"):
            print(f"{Fore.RED}\u2718 [HW ACCELERATOR ATTESTATION SERVICE] Failed Attestation")
            print("Exiting...")
            print("-----------------------------------------------------------------")
            secure_client_socket.close()

        elif (data_received_utf8 == "pass"):
            print(f"{Fore.GREEN}\u2713 [HW ACCELERATOR ATTESTATION SERVICE] Successful Attestation") 
            print("-----------------------------------------------------------------")

            # --------------------------------------------------------------------------------------
            # Proceed with the remote attestation of the accelerated kernel
            data_received = secure_client_socket.recv(1024)
            data_received_utf8 = data_received.decode('utf-8')

            if (data_received_utf8[0:16] == att_request_kernel):
                print("\n-----------------------------------------------------------------")
                print("VERYFING FPGA ACCELERATOR KERNEL")
                print("-----------------------------------------------------------------")
                print("Input file:", xclbin_file)

                # Get the nonce value
                nonce = data_received_utf8[16:32]
                print("Received Nonce:", nonce)

                # Remote attestation function
                attestation_report = attestation_accelerated_kernel(nonce, xclbin_file)

                # Send attestation report to the verification server
                print("-----------------------------------------------------------------")
                print("Sending Attestation report to the Verification Server...")
                # print(attestation_report.hex()) # WORKING
                print(attestation_report)

                secure_client_socket.sendall(attestation_report.encode('utf-8'))
                # secure_client_socket.sendall(attestation_report) # WORKING

                print("-----------------------------------------------------------------")
                print("Waiting for response...")

                data_received = secure_client_socket.recv(1024)
                data_received_utf8 = data_received.decode('utf-8')

                if data_received_utf8 == "fail":
                    print(f"{Fore.RED}\u2718 [FPGA BITSTREAM] Failed Attestation")
                    print("Exiting...")
                    print("-----------------------------------------------------------------")
                    secure_client_socket.close()


                elif data_received_utf8 == "pass":
                    print(f"{Fore.GREEN}\u2713 [FPGA BITSTREAM] Successful Attestation") 
                    print("-----------------------------------------------------------------")

                    # Request the bitstream decryption key
                    print("\n-----------------------------------------------------------------")
                    print("BITSTREAM DECRYPTION")
                    print("-----------------------------------------------------------------")
                    # print("Getting bitstream decryption key from the server using ECHD...")
                    print("Generating shared secret with ECDH")
                    print("Getting bitstream decryption key...")
                    bitstr_key_rqst = "bitstr_key"
                    secure_client_socket.sendall(bitstr_key_rqst.encode('utf-8'))

                    # Exchange the key using ECDH
                    client_ecdh = DiffieHellman()

                    # Exchange public keys with the client
                    public_key_received = secure_client_socket.recv(1024)
                    public_key_received_utf8 = public_key_received.decode('utf-8')
                    public_key_received_bytes = bytes.fromhex(public_key_received_utf8)
                    public_key_received_object = get_key_object(public_key_received_bytes)
                    public_key_hex = get_key_hex(client_ecdh.public_key)
                    secure_client_socket.sendall(public_key_hex.encode('utf-8'))

                    # Complete the key exchange
                    data_received = secure_client_socket.recv(1024)
                    data_received_utf8 = data_received.decode('utf-8')
                    data_received_bytes = bytes.fromhex(data_received_utf8)
                    bitstr_decryption_key = client_ecdh.decrypt(public_key_received_object, data_received_bytes, client_ecdh.IV)
                    print("Key Derivation Completed")

                    # Decrypt the bitstream and build the xclbin file
                    bitstream_decryption(xclbin_file, xclbin_output_file, bitstr_decryption_key)
                    
                    # Load the .xclbin application to the FPGA
                    print("\n-----------------------------------------------------------------")
                    print("LOAD THE BITSTREAM TO THE FPGA")
                    print("-----------------------------------------------------------------")
                    print("Loading the bitstream to the HW accelerator...")            
                    print("Attestation Execution time: {:.2f} sec".format(time.time() - start_time))
                    print("-----------------------------------------------------------------")

                    subprocess.run(["xbutil", "program", "-d", "0000:bf:00.1", "-u", xclbin_output_file])

    else:
        print("[Error] - Received: {}".format(data_received_utf8))

        # Close the connection
        secure_client_socket.close()

if __name__ == "__main__":
    main()
