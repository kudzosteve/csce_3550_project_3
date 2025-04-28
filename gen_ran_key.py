"""Generate a random key for encryption and decryption"""
import base64, os

ENV = "NOT_MY_KEY"

# Generate a secure random 32-byte key
key = os.urandom(32)

# Convert to base64 for easy storage as an environment variable
encoded_key = base64.b64encode(key).decode('utf-8')
print(f"Generated key: {encoded_key}")