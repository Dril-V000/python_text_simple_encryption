import os
import base64
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_key_from_password(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))

def encrypt(text, password):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)
    token = cipher.encrypt(text.encode()).decode()
    salt_b64 = base64.urlsafe_b64encode(salt).decode()
    return f"{salt_b64}:{token}"

def decrypt(prefixed, password):
    try:
        salt_b64, token = prefixed.split(":", 1)
    except ValueError:
        raise ValueError("?????? salt:token")
    salt = base64.urlsafe_b64decode(salt_b64.encode())
    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)
    return cipher.decrypt(token.encode()).decode()

def main():
    print("=== Simple Password-based Cipher (Salted) ===")
    while True:
        print("\nChoose an operation:")
        print("1) Encrypt")
        print("2) Decrypt")
        print("3) Exit")
        choice = input("Your choice (1/2/3): ").strip()
        if choice == '1':
            password = input("Enter the password: ")
            text = input("Enter the text to encrypt: ")
            encrypted = encrypt(text, password)
            print("\nEncrypted text:")
            print(encrypted)
        elif choice == '2':
            password = input("Enter the password: ")
            token = input("Enter the encrypted text: ")
            try:
                decrypted = decrypt(token, password)
                print("\nDecrypted text:")
                print(decrypted)
            except Exception:
                print("\nError: wrong password or invalid text!")
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user. Bye!")
        sys.exit(0)
