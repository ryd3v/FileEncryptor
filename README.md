# FileEncryptor Program

## Overview

This File Encryption Program is a Python-based tool designed to securely encrypt and decrypt large files using a
password-derived key. It employs robust cryptographic methods, including the Argon2 algorithm for key derivation and
AES-GCM for encryption, making it suitable for processing large files efficiently.

## Features

- **AES-GCM Encryption**: Utilizes AES-GCM for secure and efficient encryption, suitable for large files.
- **Password-Based Encryption**: Generates a secure encryption key based on a user-provided password.
- **File Encryption and Decryption**: Encrypts files with a `.enc` extension and decrypts them back to their original
  state.
- **Chunked File Processing**: Processes files in chunks to efficiently handle large files without excessive memory
  usage.
- **Progress Bar**: Displays a progress bar during encryption and decryption processes for better user feedback.
- **Secure Key Management**: Securely stores the encryption key in an encrypted file, ensuring access only for the
  password holder.

## Requirements

- Python 3.x
- Cryptography library
- Argon2 library

## Installation

1. Ensure Python 3.x is installed on your system.
2. Install required Python libraries:
   ```
   pip install -r requirements.txt
   ```

## Usage

Navigate to the program's directory in the command line and use the following commands:

1. **Encrypt a File**:
   ```
   python3 ./FileEncryptor encrypt <file_path>
   ```
   This command encrypts the specified file and saves it with a `.enc` extension.

2. **Decrypt a File**:
   ```
   python3 ./FileEncryptor decrypt <file_path>.enc
   ```
   This decrypts the specified `.enc` file back to its original format.

### First Run

- The program prompts the user for a password to generate a secure encryption key upon first execution.

### Subsequent Runs

- Enter the same password used during the first run to decrypt the key file and access the encryption/decryption
  functionality.

## Security

- Employs `750000` iterations in the key derivation process for enhanced security.
- The master key is securely stored in an encrypted file, accessible only with the correct password.

## Disclaimer

- This tool is intended for educational purposes and should be thoroughly tested before using it for sensitive data.

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
