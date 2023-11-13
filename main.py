import base64
import getpass
import os
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key(password: str, salt: bytes = None) -> (bytes, bytes):
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=750000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key), salt


def encrypt_key_file(key: bytes, password: str):
    generated_key, salt = generate_key(password)
    fernet = Fernet(generated_key)
    encrypted_key = fernet.encrypt(key)
    with open('key_file', 'wb') as file:
        file.write(salt + encrypted_key)


def decrypt_key_file(password: str) -> bytes:
    with open('key_file', 'rb') as file:
        salt = file.read(16)
        encrypted_key = file.read()

    key = generate_key(password, salt)[0]
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_key)


def encrypt_file(file_path: str, key: bytes):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)

    print(f"File {file_path} has been encrypted to {encrypted_file_path}.")


def decrypt_file(file_path: str, key: bytes):
    if not file_path.endswith(".enc"):
        print("The file does not have the correct '.enc' extension.")
        return

    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    decrypted_file_path = file_path.rsplit(".enc", 1)[0]
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    print(f"File {file_path} has been decrypted to {decrypted_file_path}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python file_encryptor.py <encrypt/decrypt> <file_path>")
        sys.exit(1)

    mode = sys.argv[1].lower()
    file_path = sys.argv[2]

    if not os.path.exists('key_file'):
        password = getpass.getpass(prompt="Enter a password to generate your key: ")
        master_key = Fernet.generate_key()
        encrypt_key_file(master_key, password)
    else:
        password = getpass.getpass(prompt="Enter your password to decrypt the key: ")
        try:
            master_key = decrypt_key_file(password)
        except Exception as e:
            print(f"Error decrypting key: wrong password? {e}")
            return

    if mode == 'encrypt':
        if os.path.isfile(file_path):
            encrypt_file(file_path, master_key)
        else:
            print("File not found.")
    elif mode == 'decrypt':
        if os.path.isfile(file_path):
            decrypt_file(file_path, master_key)
        else:
            print("File not found.")
    else:
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")


if __name__ == "__main__":
    main()
