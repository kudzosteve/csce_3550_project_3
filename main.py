from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
import sqlite3, threading, time, uuid
import base64, json, jwt, os

#--------------------------------------------------
# CONSTANT VARIABLES
#--------------------------------------------------

DB_FILE = os.path.abspath(os.path.join(os.getcwd(), "totally_not_my_privateKeys.db"))

# Get the encryption/decryption key from the environment variable
encoded_key = os.environ.get("NOT_MY_KEY")
if not encoded_key:
    raise ValueError("Environment variable 'NOT_MY_KEY' not set")

ENV_KEY = base64.b64decode(encoded_key)  # Convert the key to bytes
IV = os.urandom(16)  # Initialization vector

#--------------------------------------------------
# RATE LIMITER IMPLEMENTATION
# USING TOKEN BUCKET ALGORITHM
#--------------------------------------------------

class TokenBucket:
    def __init__(self, capacity, refill_rate=1):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_check = time.monotonic()
        self.lock = threading.Lock()

    def handle(self, ip):
        now = time.monotonic()
        elapsed = now - self.last_check
        self.last_check = now
        with self.lock:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            else:
                return False

# Initialize the rate limiter with 10 requests per second
rate_limiter = TokenBucket(10)

#--------------------------------------------------
# KEY MANAGEMENT
#--------------------------------------------------

class Key:
    """ Class to hold key data structure """
    def __init__(self, kid, key_data, exp):
        self.kid = kid
        self.key = key_data  # The actual key data
        self.exp = exp

def encrypt_key(key):
    """ Apply AES encryption to generated keys """
    padder = padding.PKCS7(algorithms.AES.block_size).padder()  # Create padder
    padded_data = padder.update(key) + padder.finalize()  # Add padding to the data
    encryptor = Cipher(algorithms.AES(ENV_KEY), modes.CBC(IV)).encryptor() # Encryptor
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()   # Encrypt the data
    return encrypted_data

def decrypt_key(encrypted_key):
    """ Decrypt AES encrypted keys """
    decryptor = Cipher(algorithms.AES(ENV_KEY), modes.CBC(IV)).decryptor()  # Decryptor
    padded_data = decryptor.update(encrypted_key) + decryptor.finalize()   # Get the padded data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()  # Remove padding from the data
    decrypted_key = unpadder.update(padded_data) + unpadder.finalize() # Decrypt the data
    return decrypted_key

def create_databases():
    """ Create a database and add the necessary tables """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        # Create the 'keys' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        # Create the 'users' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        # Create the 'auth_logs' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

    # Check if database contains keys before generating
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]  # check the first row
    # If there are no keys, generate them
    if count == 0:
        generate_keys()

def generate_keys():
    """ Generate RSA keys, encrypt them, and store them in the database """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize the private keys to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt the private keys
    encrypted_pem = encrypt_key(pem)
    encrypted_expired = encrypt_key(expired_pem)

    # Generate expiry timestamps
    pem_timestamp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())  # expires in 1 hour
    expired_timestamp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())  # expired 1 hour ago

    # Insert the keys and their timestamp into the database
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)",
                      (sqlite3.Binary(encrypted_pem), pem_timestamp))
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)",
                      (sqlite3.Binary(encrypted_expired), expired_timestamp))

def get_key(expired=False):
    """ Retrieve a key from the database based on expiry query """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        current_time = int(datetime.now(timezone.utc).timestamp())
        # Retrieve a key from the database based on expiry
        if expired:
            cursor.execute("SELECT kid, key, iv, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                          (current_time,))
        else:
            cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
                          (current_time,))
        result = cursor.fetchone()

    if result:
        kid, encrypted_key, exp = result[0], bytes(result[1]), result[2]
        decrypted_key = decrypt_key(encrypted_key)
        return Key(kid, decrypted_key, exp)
    else:
        return None

def get_valid_keys():
    """ Retrieve all non-expired keys from the database """
    curr_time = int(datetime.now(timezone.utc).timestamp())
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (curr_time,))
        results = cursor.fetchall()

    decrypted_results = []
    for result in results:
        kid, encrypted_key, exp = result[0], bytes(result[1]), result[2]
        decrypted_key = decrypt_key(encrypted_key)

        # Create a key object with the appropriate structure
        key_obj = Key(kid, decrypted_key, exp)
        decrypted_results.append(key_obj)
    return decrypted_results

# Register a new user with their credentials
def register(username, email):
    """ Generate a password using UUID4 and hash it with the Argon2 algorithm """
    password = str(uuid.uuid4())
    ph = PasswordHasher()
    hashed_password = ph.hash(password)

    # Add the new user's information into the database
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?,?,?)",
                          (username, hashed_password, email))
            return password
        except sqlite3.IntegrityError:
            return None

def get_user_id(username):
    """ Retrieve the associated ID to a username from the database """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users where username=?", (username,))
        result = cursor.fetchone()
    return result[0] if result else None

def log_auth_request(request_ip, username):
    """ Logg authentication requests into the database """
    user_id = get_user_id(username) if username else None
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?,?)",
                      (request_ip, user_id))

# Encode keys with base64 encoding
def int_to_base64(value):
    """ Convert an integer number to a Base64URL-encoded string """
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

#--------------------------------------------------
# WEB SERVER
#--------------------------------------------------

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def get_client_ip(self):
        # Check the X-Forwarded-For header first for client IP addresses
        forwarded_for = self.headers.get("X-Forwarded-For")
        # Get the first IP address from the header,
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        return self.client_address[0] # otherwise, get the connecting client IP

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            client_ip = self.get_client_ip()    # Get the client IP address
            if not rate_limiter.handle(client_ip):  # Rate limit the requests
                self.send_response(429)  # Too Many Requests
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Rate limit exceeded"}).encode("utf-8"))
                return

            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            username = None

            # Try to extract username from request if present
            try:
                data = json.loads(post_data)
                username = data.get("username")
            except:
                pass

            # Get a key based on the "expired" parameter
            use_expired = "expired" in params
            key_obj = get_key(expired=use_expired)

            if key_obj:
                if use_expired:
                    token_exp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
                else:
                    token_exp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())

                # Header and payload for the JWT
                headers = {
                    "kid": str(key_obj.kid)
                }
                token_payload = {
                    "user": username or "username",
                    "exp": token_exp
                }
                try:
                    # Load the private key and sign a token
                    private_key = serialization.load_pem_private_key(key_obj.key, password=None)
                    encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)

                    self.send_response(200)
                    self.send_header("Content-type", "application/jwt")
                    self.end_headers()
                    self.wfile.write(bytes(encoded_jwt, "utf-8"))

                    log_auth_request(client_ip, username)   # Log successful authentication
                    return
                except Exception as e:
                    self.send_response(500)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(f"Error signing JWT: {str(e)}".encode("utf-8"))
                    return
            else:
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write("No suitable key found".encode("utf-8"))
                return

        elif parsed_path.path == "/register":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)

            try:
                data = json.loads(post_data)    # Data from the POST request
                username = data.get("username") # Retrieve the username
                email = data.get("email")       # Retrieve the password

                if not username or not email:
                    self.send_response(400)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "username and email are required"}).encode("utf-8"))
                    return

                password = register(username, email)    # Store user credentials to the database
                if password:
                    self.send_response(201)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"password": password}).encode("utf-8"))
                    return
                else:
                    self.send_response(409)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "username or email already exists"}).encode("utf-8"))
                    return

            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode("utf-8"))
                return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            valid_keys = get_valid_keys()
            jwks = {"keys": []}

            for key_obj in valid_keys:
                private_key = serialization.load_pem_private_key(key_obj.key, password=None)
                numbers = private_key.public_key().public_numbers()
                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(key_obj.kid),
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    create_databases()  # Set up the database
    if not os.path.exists(DB_FILE):
        print(f"Database not found: {DB_FILE}")
        exit(1)

    # Start the web server
    webServer = HTTPServer(("localhost", 8080), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()