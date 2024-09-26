import krnl_aes_decrypt

# Open the .xclbin file in binary read mode
# with open('krnl_aes_test_hw.xclbin', 'rb') as file:
with open('enc.xclbin', 'rb') as file:
    # Read the binary content of the file
    binary_content = file.read()

# Convert the binary content to a string (you can convert it as per the desired format)
# One way is to decode it using utf-8 or handle it as a hex string
# Assuming you want to convert it to a hex string for easier handling
hex_string = binary_content.hex()

# Now hex_string contains the parsed file data as a hex string
key = "a3f9b2e8c4d1a6b0e7f5c9d2a4b8f3e6c1d7a0b9e5f2c4d8a3b6e0f1c9d2a5b7"

decrypted_file = krnl_aes_decrypt.aes_decrypt_kernel(key, hex_string)

# Function to decrypt large files in chunks
def decrypt_large_file(input_filename, output_filename, key, chunk_size=65536*1024):  # 64KB chunks by default
    with open(input_filename, 'rb') as infile, open(output_filename, 'wb') as outfile:
        while True:
            # Read a chunk of the file
            chunk = infile.read(chunk_size)
            if not chunk:
                break  # End of file
            
            # Convert the binary chunk to hex string (if needed)
            hex_chunk = chunk.hex()

            # Decrypt the chunk
            decrypted_chunk = krnl_aes_decrypt.aes_decrypt_kernel(key, hex_chunk)
            
            # Convert the decrypted hex string back to bytes and write it to the output file
            outfile.write(bytes.fromhex(decrypted_chunk))

# Key for AES decryption
key = "a3f9b2e8c4d1a6b0e7f5c9d2a4b8f3e6c1d7a0b9e5f2c4d8a3b6e0f1c9d2a5b7"

# Decrypt the large .xclbin file
# decrypt_large_file('krnl_aes_test_hw.xclbin', 'krnl_aes_test_decrypted.bin', key)
