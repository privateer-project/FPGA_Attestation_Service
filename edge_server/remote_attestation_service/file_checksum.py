# ---------------------------------------------------
# Example code for file checksum calculation
# ---------------------------------------------------
# Includes
import hashlib

# ---------------------------------------------------

# Function to Calculate SHA-256 checksum
def calculate_sha256_checksum(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        # Read the file in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256.update(byte_block)
    return sha256.hexdigest()

# File to calculate checksum for
# input_file_1 = "bitstream/bitstream_lstm_1.bit"
# input_file_2 = "bitstream/bitstream_lstm_2.bit"

# Print the SHA-256 checksum
# checksum_1 = calculate_sha256_checksum(input_file_1)
# print("Filename [{}]".format(input_file_1))
# print("SHA256 Checksum : {}".format(checksum_1))

# checksum_2 = calculate_sha256_checksum(input_file_2)
# print("Filename [{}]".format(input_file_2))
# print("SHA256 Checksum : {}".format(checksum_2))
