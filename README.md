# CSCE 3550 - JKWS Server Project

## Details
This project simulates a JWKS server with a RESTful API that can serve public keys with expiry and unique kid to verify JWTs. The keys are AES encrypted and stored in a SQLite database. The /auth endpoint is set to handle 10 requests per seconds and every successful authentication is logged.

## Project structure
```text
csce_3550_project_3/
├─screenshots/
├─gen_ran_key.py
├─gradebot
├─main.py
├─README.md
└─requirements.txt
```

## Prerequisites
- OS: Linux (amd64)
- Python 3.12+ with pip
- Dependencies from requirements.txt

## Installation Steps
### Download the project and navigate to the directory
```bash
git clone <repository_url>
cd <repository_directory>
```

### Set up a virtual environment
```bash
# Set up the virtual environment 
python3 -m venv .venv

# Activate the virtual environment
source venv/bin/activate

# Install the necessary packages
pip install -r requirements.txt
```

### Start the server
```bash
# Generate random 32-bit key for encryption and decryption
python3 gen_key.py

# Example output 
Generated key: 8HP6TOgxYweuwxJWNehdCfQW327NMTIdJpJCOk/PYCE=

# Export the generated key
export NOT_MY_KEY="8HP6TOgxYweuwxJWNehdCfQW327NMTIdJpJCOk/PYCE="

# Now, run the main program to start the server
python3 main.py
```

### Open a second terminal and run the test suite

```bash
# Activate the virtual environment
source venv/bin/activate

# Run the tests
./gradebot project3
```

## Screenshots showing outputs in Ubuntu
### Server side
![JWKS server](./screenshots/server%20running.png)

### Client side
![Test suite](./screenshots/test%20suite%20output.png)

## Server Details
- Address: `localhost:8080`.
- Database: `totally_not_my_privateKeys.db`
- Environment key: `NOT_MY_KEY`
- Test suite: `gradebot` 