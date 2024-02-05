import getpass
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tqdm import tqdm


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
    return key, salt


def encrypt_key_file(key: bytes, password: str):
    generated_key, salt = generate_key(password)
    aesgcm = AESGCM(generated_key)
    nonce = os.urandom(12)

    encrypted_key = aesgcm.encrypt(nonce, key, None)
    with open('key', 'wb') as file:
        file.write(salt + nonce + encrypted_key)


def decrypt_key_file(password: str) -> bytes:
    with open('key', 'rb') as file:
        salt = file.read(16)
        nonce = file.read(12)
        encrypted_key = file.read()

    key = generate_key(password, salt)[0]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_key, None)


def encrypt_file(file_path: str, key: bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    chunk_size = 1024 * 1024  # 1MB chunk size
    encrypted_file_path = file_path + ".enc"

    total_size = os.path.getsize(file_path)

    with open(file_path, 'rb') as input_file:
        with open(encrypted_file_path, 'wb') as output_file:
            output_file.write(nonce)
            with tqdm(total=total_size, unit='B', unit_scale=True, desc="Encrypting") as pbar:
                while True:
                    chunk = input_file.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    output_file.write(encrypted_chunk)
                    pbar.update(len(chunk))

    print(f"File {file_path} has been encrypted to {encrypted_file_path}")


def decrypt_file(file_path: str, key: bytes):
    if not file_path.endswith(".enc"):
        print("The file does not have the correct '.enc' extension.")
        return

    aesgcm = AESGCM(key)
    tag_length = 16

    chunk_size = 1024 * 1024
    decrypted_file_path = file_path.rsplit(".enc", 1)[0]

    total_size = os.path.getsize(file_path)

    with open(file_path, 'rb') as input_file:
        nonce = input_file.read(12)
        total_size -= len(nonce)

        with open(decrypted_file_path, 'wb') as output_file:
            with tqdm(total=total_size, unit='B', unit_scale=True, desc="Decrypting") as pbar:
                while True:
                    encrypted_chunk = input_file.read(chunk_size + tag_length)
                    if len(encrypted_chunk) == 0:
                        break
                    decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
                    output_file.write(decrypted_chunk)
                    pbar.update(len(encrypted_chunk) - tag_length)

    print(f"File {file_path} has been decrypted to {decrypted_file_path}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python file_encryptor.py <encrypt/decrypt> <file_path>")
        sys.exit(1)

    mode = sys.argv[1].lower()
    file_path = sys.argv[2]

    if not os.path.exists('key'):
        password = getpass.getpass(prompt="Enter a password to generate your key: ")
        master_key, _ = generate_key(password)  # Generate a raw key suitable for AESGCM
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
