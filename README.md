# csce_3550_project_3
# README - Running the JWT Authentication Server on Linux

## Prerequisites
Ensure your system has the following installed:
- Python 3.12+
- `pip` (Python package manager)
- Required Python dependencies

## Installation Steps
1. Clone the repository or download the files and save them in the same directory
    ```
    git clone <repository_url>
    cd <repository_directory>
    ```

    **The following files should be present in the directory. Check with `ls -l` command**
        - gen_ran_key.py        # the program that will generate the encryption/decryption key
        - gradebot              # the test client
        - main.py               # the main program
        - requirements.txt      # the required dependencies
        - venv                  # virtual environment

2. Setup virtual environment and install required dependencies
    a. Make sure pip is installed or install with:
        ```
        sudo apt install python3-pip
        ```
    b. Set up the virtual environment
        ```
        python3 -m venv venv
        ```
    Note: Creating the virtual environment within a hidden file (like .venv) has proven to not run the server as expected

    c. Activate the virtual environment with:
        ```
        source venv/bin/activate
        ```
    d. Install the packages from the requirements.txt file
        ```
        pip install -r requirements.txt
        ```
3. Open a second terminal and navigate to the folder containing the "gradebot" program that will verify the server runs as expected
    a. Generate the key by running the command: python3 gen_ran_key.py. A random key will be printed to the terminal

    b. Copy the generated key and run the command: export NOT_MY_KEY="***The generated key***"

    Example:
        Example:
        Generated key: 8HP6TOgxYweuwxJWNehdCfQW327NMTIdJpJCOk/PYCE=
        export NOT_MY_KEY="8HP6TOgxYweuwxJWNehdCfQW327NMTIdJpJCOk/PYCE="

    c. Run the server in the first terminal
        ```
        python3 main.py
        ```

    d. Execute the "gradebot" program in the second terminal.
        ```
        ./gradebot project2
        ```
    You should see some outputs in the first terminal after the test client has executed

## Server Details
- The server runs on `localhost:8080`.
- The database file is created at "totally_not_my_privateKeys.db" in the script's directory.

## Troubleshooting
If the gradebot does not output a total score of 65, try these fixes:
    a. Remove the "totally_not_my_privateKeys.db" with `rm totally_not_my_privateKeys.db` and run the program again
    b. Deactivate the virtual environment with `deactivate` and run the program again, with "totally_not_my_privateKeys.db" not in the directory
