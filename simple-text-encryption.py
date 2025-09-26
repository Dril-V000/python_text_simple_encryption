import base64
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_key_from_password(password: str, salt: bytes = b"fixed_salt_here") -> bytes:
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))

def encrypt(text, password):
    key = generate_key_from_password(str(password))
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt(token, password):
    key = generate_key_from_password(str(password))
    cipher = Fernet(key)
    return cipher.decrypt(token.encode()).decode()

def main():
    print("=== Simple Password-based Cipher ===")
    while True:
        print("\nChoose an operation:")
        print("1) Encrypt")
        print("2) Decrypt")
        print("3) Exit")
        choice = input("Your choice (1/2/3): ").strip()
        if choice == '1':
            password = input("Enter the password: ")
            if not password.isdigit():
                print("Only numbers allowed")
                exit()
            px = int(password)
            passx = str(px + 199)
            psxx = str((px + 199) * 3)
            text = input("Enter the text to encrypt: ")
            encrypted1 = encrypt(text, password)
            encrypted2 = encrypt(encrypted1, passx)
            encrypted3 = encrypt(encrypted2, psxx)
            print("\nEncrypted text:")
            print(encrypted3)
        elif choice == '2':
            password = input("Enter the password: ")
            if not password.isdigit():
                print("Only numbers allowed")
                exit()
            px = int(password)
            passx = str(px + 199)
            psxx = str((px + 199) * 3)
            token = input("Enter the encrypted text: ")
            try:
                decrypted2 = decrypt(token, psxx)
                decrypted1 = decrypt(decrypted2, passx)
                decrypted = decrypt(decrypted1, password)
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
