# ---------------------------------------------------
# Example code for file checksum calculation
#
# Ilias Papalamprou
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
file_name = input("Filename : ")
file_path = "bitstream/{}".format(file_name)

# Print the SHA-256 checksum
checksum_1 = calculate_sha256_checksum(file_path)
print("Filename [{}]".format(file_path))
print("SHA256 Checksum : {}".format(checksum_1))
