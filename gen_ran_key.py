# Generate a random key for encryption and decryption
import os, base64

# Generate a 32-bit random key
env_key = os.urandom(32)
encoded_key = base64.b64encode(env_key).decode('utf-8')
print(f"The key: {encoded_key}")