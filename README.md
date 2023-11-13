# File Encryptor Program

## Overview

This File Encryption Program is a Python-based tool designed to securely encrypt and decrypt files using a
password-derived key. It uses robust cryptographic methods, including the Argon2 algorithm for key derivation and Fernet
symmetric encryption.

## Features

- **Password-Based Encryption**: Generates a secure encryption key based on a user-provided password.
- **File Encryption and Decryption**: Allows users to encrypt files, adding a `.enc` extension, and decrypt them back to
  their original state.
- **Secure Key Management**: Securely stores the encryption key in an encrypted file, ensuring that only the password
  holder can access it.

## Requirements

- Python 3.x
- Cryptography library
- Argon2 library

## Installation

1. Ensure Python 3.x is installed on your system.
2. Install required Python libraries:
   ```
   pip install cryptography argon2-cffi
   ```

## Usage

To use the File Encryption Program, navigate to the program's directory in the command line and use the following
commands:

1. **Encrypt a File**:
   ```
   python3 main.py encrypt <file_path>
   ```
   This will encrypt the specified file and save it with a `.enc` extension.

2. **Decrypt a File**:
   ```
   python3 main.py decrypt <file_path>.enc
   ```
   This will decrypt the specified `.enc` file back to its original format.

### First Run

- Upon first execution, the program will prompt you to enter a password to generate a secure encryption key. This key
  will be used for all encryption and decryption processes.

### Subsequent Runs

- On subsequent runs, you'll need to enter the same password to decrypt the key file and access the
  encryption/decryption functionality.

## Security

- The program uses `750000` iterations in the key derivation process for enhanced security.
- The primary key is securely stored in an encrypted file, accessible only with the correct password.

## Disclaimer

- This tool is for educational purposes and should be thoroughly tested before using it for sensitive data.

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
