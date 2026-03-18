from fastecdsa import curve, ecdsa, keys
from fastecdsa.keys import export_key, import_key, gen_keypair
from hashlib import sha384
import os
import struct

# Function to generate and save keys
def generate_and_save_keys(private_key_path, public_key_path):
    # Generate key pair
    d, Q = gen_keypair(curve.P256)
    
    # Save the private key to disk
    export_key(d, curve=curve.P256, filepath=private_key_path)
    print(f"Private key saved to: {private_key_path}")
    
    # Save the public key to disk
    export_key(Q, curve=curve.P256, filepath=public_key_path)
    print(f"Public key saved to: {public_key_path}")


private_key_path = 'private_key_ecdsa.pem'
public_key_path = 'public_key_ecdsa.pem'
generate_and_save_keys(private_key_path, public_key_path)


"""
from ecdsa import SigningKey, NIST256p, VerifyingKey

# ECDSA
private_key = SigningKey.generate(curve=NIST256p) 
public_key = private_key.get_verifying_key()

# Save keys to file
with open("private_key_ecdsa.pem", "wb") as f:
    f.write(private_key.to_pem(format="pkcs8"))

with open("public_key_ecdsa.pem", "wb") as f:
    f.write(public_key.to_pem())
"""

# Falcon
from pqc.sign import falcon_1024 as sigalg

pk, sk = sigalg.keypair()

# Define file names
public_key_file = "public_key_f1024.pem"
private_key_file = "private_key_f1024.pem"

# Write the public key to a file
with open(public_key_file, 'wb') as pub_file:
    pub_file.write(pk)

# Write the private key to a file
with open(private_key_file, 'wb') as priv_file:
    priv_file.write(sk)


# Dilithium
from pqc.sign import dilithium5 as sigalg

pk, sk = sigalg.keypair()

# Define file names
public_key_file = "public_key_d5.pem"
private_key_file = "private_key_d5.pem"

# Write the public key to a file
with open(public_key_file, 'wb') as pub_file:
    pub_file.write(pk)

# Write the private key to a file
with open(private_key_file, 'wb') as priv_file:
    priv_file.write(sk)
