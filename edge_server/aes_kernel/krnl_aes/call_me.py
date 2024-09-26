import krnl_aes_encrypt

# key = "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
key = "a3f9b2e8c4d1a6b0e7f5c9d2a4b8f3e6c1d7a0b9e5f2c4d8a3b6e0f1c9d2a5b7"

plaintext = "c25f19b27fbd40462afe2f2a9bd500bba2e72e4a10d9cb4a49310dc06517a244cf66b598d74c49e6f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99c25f19b27fbd40462afe2f2a9bd500bba2e72e4a10d9cb4a49310dc06517a244cf66b598d74c49e6f8e2a7b1d6934c0f9dc5450e76a91b6e5e257db4c52e9f062d2464937d3a1c99"

result = krnl_aes_encrypt.aes_encrypt_kernel(key, plaintext)

print("********** PYTHON RESULTS ***********")
print(result)
