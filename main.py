from http.server import BaseHTTPRequestHandler, HTTPServer
from json import JSONDecodeError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
import threading
import base64, json
import jwt, sqlite3
import os, uuid, time

hostName = "localhost"
serverPort = 8080
db_file = os.path.abspath(os.path.join(os.getcwd(), "totally_not_my_privateKeys.db"))

# Get environment variable and decode it from base64
encoded_key = os.environ.get("NOT_MY_KEY")
if not encoded_key:
    raise ValueError("Environment variable 'NOT_MY_KEY' not set")
encryption_key = base64.b64decode(encoded_key)  # Properly decode the base64 key


# Rate limiter implementation using token bucket algorithm
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

# Initialize rate limiter with 10 requests per second
rate_limiter = TokenBucket(10)


def encrypt_key(a_key):
    """
    Encrypt a private key using AES-CBC with PKCS7 padding.
    Returns a tuple of (encrypted_data, iv) where iv is the initialization vector.
    """
    iv = os.urandom(16)  # Generate random initialization vector

    # Create a padder
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(a_key) + padder.finalize()

    # Create an encryptor
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data, iv


def decrypt_key(encrypted_data, iv):
    """
    Decrypt an encrypted private key using AES-CBC with PKCS7 padding.
    """
    # Create a decryptor
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt data
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data


def create_databases():
    """Create tables in the database"""
    # Connect to database and create cursor
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()

    # Create 'keys' table with correct structure matching expected by grader
    db_cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            iv BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)

    # Create 'users' table
    db_cursor.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)

    # Create 'auth_logs' table
    db_cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Commit changes and close connection
    db_connect.commit()
    db_connect.close()

    # Check if database contains keys before generating
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()
    db_cursor.execute("SELECT COUNT(*) FROM keys")
    count = db_cursor.fetchone()[0]  # check the first row
    db_connect.close()

    # if there are no keys, generate them
    if count == 0:
        generate_keys()


def generate_keys():
    """Generate RSA keys, encrypt them, and store them in the database"""
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
    encrypted_pem, pem_iv = encrypt_key(pem)
    encrypted_expired, expired_iv = encrypt_key(expired_pem)

    # Generate expiry timestamps
    pem_timestamp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())  # expires in 1 hour
    expired_timestamp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())  # expires 1 hour ago

    # Establish connection to the database and create cursor
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()

    # Insert data into the database
    db_cursor.execute("INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)",
                      (sqlite3.Binary(encrypted_pem), sqlite3.Binary(pem_iv), pem_timestamp))
    db_cursor.execute("INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)",
                      (sqlite3.Binary(encrypted_expired), sqlite3.Binary(expired_iv), expired_timestamp))

    # Commit changes to the database and close connection
    db_connect.commit()
    db_connect.close()


class key:
    """
    Class to hold key data structure for compatibility with the testing framework
    """
    def __init__(self, kid, key_data, exp, iv):
        self.kid = kid
        self.key = key_data  # The actual key data
        self.exp = exp
        self.iv = iv


def get_key(expired=False):
    """Retrieve a key from the database based on expiry"""
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())

    if expired:
        db_cursor.execute("SELECT kid, key, iv, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                          (current_time,))
    else:
        db_cursor.execute("SELECT kid, key, iv, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
                          (current_time,))

    result = db_cursor.fetchone()
    db_connect.close()

    if result:
        kid, encrypted_key, iv, exp = result[0], bytes(result[1]), bytes(result[2]), result[3]
        decrypted_key = decrypt_key(encrypted_key, iv)

        # Create a key object with the appropriate structure, ensuring iv is passed
        return key(kid, decrypted_key, exp, iv)
    else:
        return None


def get_all_valid_keys():
    """Retrieve all valid keys from the database"""
    current_time = int(datetime.now(timezone.utc).timestamp())
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()
    db_cursor.execute("SELECT kid, key, iv, exp FROM keys WHERE exp > ?", (current_time,))
    results = db_cursor.fetchall()
    db_connect.close()

    decrypted_results = []
    for result in results:
        kid, encrypted_key, iv, exp = result[0], bytes(result[1]), bytes(result[2]), result[3]
        decrypted_key = decrypt_key(encrypted_key, iv)

        # Create a key object with the appropriate structure, ensuring iv is passed
        key_obj = key(kid, decrypted_key, exp, iv)
        decrypted_results.append(key_obj)

    return decrypted_results


# Register a new user with their credentials
def register(username, email):
    """Generate a password using UUID4
        and hash it using Argon2 algorithm"""
    password = str(uuid.uuid4())
    ph = PasswordHasher()
    hashed_password = ph.hash(password)

    # Connect to database and create cursor
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()

    try:
        # Add the new user's information to the database
        db_cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?,?,?)",
                          (username, hashed_password, email)
                          )
        db_connect.commit()
        return password
    except sqlite3.IntegrityError:
        return None
    finally:
        db_connect.close()


def get_user_id(username):
    """Retrieve the user ID"""
    # Connect to database and create cursor
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()
    db_cursor.execute("SELECT id FROM users where username=?", (username,))
    result = db_cursor.fetchone()
    db_connect.close()

    return result[0] if result else None


def log_auth_request(request_ip, username):
    """Logging Authentication Requests"""
    user_id = get_user_id(username) if username else None
    current_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Connect to database and create cursor
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()
    db_cursor.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?,?,?)",
                      (request_ip, current_timestamp, user_id)
                      )
    db_connect.commit()
    db_connect.close()


# Encode keys with base64 encoding
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex

    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


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
        """Get client IP address"""
        # Check for X-Forwarded-For header first (for clients behind proxy)
        forwarded_for = self.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()

        # Fall back to the direct client address
        return self.client_address[0]

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Get client IP and apply rate limiting
            client_ip = self.get_client_ip()

            # Check rate limit before processing further
            if not rate_limiter.handle(client_ip):
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
                kid = key_obj.kid
                priv_bytes = key_obj.key
                exp = key_obj.exp

                # now load the PrivateKey from the bytes
                private_key = serialization.load_pem_private_key(priv_bytes, password=None)

                headers = {
                    "kid": str(kid)
                }

                if use_expired:
                    # Create a token that is already expired
                    token_exp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
                else:
                    # Create a token that expires in 1 hour
                    token_exp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())

                token_payload = {
                    "user": username or "username",
                    "exp": token_exp
                }

                try:
                    # Load the private key
                    private_key = serialization.load_pem_private_key(priv_bytes, password=None)
                    # Sign the token
                    encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)

                    self.send_response(200)
                    self.send_header("Content-type", "application/jwt")
                    self.end_headers()
                    self.wfile.write(bytes(encoded_jwt, "utf-8"))

                    # Log successful authentication
                    log_auth_request(client_ip, username)
                    return
                except Exception as e:
                    self.send_response(500)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(f"Error signing JWT: {str(e)}".encode('utf-8'))
                    return
            else:
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"No suitable key found")
                return

        elif parsed_path.path == "/register":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)

            try:
                data = json.loads(post_data)
                username = data.get("username")
                email = data.get("email")

                if not username or not email:
                    self.send_response(400)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Username and email are required"}).encode("utf-8"))
                    return

                password = register(username, email)
                if password:
                    self.send_response(200)  # OK status code
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"password": password}).encode("utf-8"))
                    return
                else:
                    self.send_response(409)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Username or email already exists"}).encode("utf-8"))
                    return

            except JSONDecodeError:
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

            valid_keys = get_all_valid_keys()
            jwks = {"keys": []}
            for key_obj in valid_keys:
                # load each RSA key from the object
                private_key = serialization.load_pem_private_key(key_obj.key, password=None)
                nums = private_key.public_key().public_numbers()

                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(key_obj.kid),
                    "n": int_to_base64(nums.n),
                    "e": int_to_base64(nums.e),
                })
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    create_databases()  # Set up the database

    if not os.path.isfile(db_file):
        print(f"Database not found: {db_file}")
        exit()

    webServer = HTTPServer((hostName, serverPort), MyServer)

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()