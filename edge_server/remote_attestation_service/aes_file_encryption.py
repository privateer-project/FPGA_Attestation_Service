# Script for file encryption
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(key, input_file_path, output_file_path):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Create an AES cipher object with the provided key and mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file_path, 'rb') as f_in, open(output_file_path, 'wb') as f_out:
        # Write the IV to the output file
        f_out.write(iv)

        # Process the file in chunks and encrypt each chunk
        chunk_size = 16  # You can adjust the chunk size as needed
        chunk = f_in.read(chunk_size)
        while chunk:
            encrypted_chunk = encryptor.update(chunk)
            f_out.write(encrypted_chunk)
            chunk = f_in.read(chunk_size)

def decrypt_file(key, input_file_path, output_file_path):
    with open(input_file_path, 'rb') as f_in, open(output_file_path, 'wb') as f_out:
        # Read the IV from the input file
        iv = f_in.read(16)

        # Create an AES cipher object with the provided key, mode, and IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Process the file in chunks and encrypt each chunk
        chunk = f_in.read(chunk_size)
        while chunk:
            encrypted_chunk = encryptor.update(chunk)
            f_out.write(encrypted_chunk)
            chunk = f_in.read(chunk_size)

# Example usage:
key = b'ffffffff'  # Replace with your 16, 24, or 32-byte key
input_file_path = 'test_files/example_1.txt'
encrypted_file_path = 'test_files/example_1.txt.enc'
decrypted_file_path = 'test_files/example_decrypted.txt'

encrypt_file(key, input_file_path, encrypted_file_path)
decrypt_file(key, encrypted_file_path, decrypted_file_path)
