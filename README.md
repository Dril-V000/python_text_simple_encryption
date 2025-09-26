# 🔐 simple-text-encryption

This is a simple Python tool for **encrypting** and **decrypting** text using a numeric password.  
It is built with the **cryptography** library and uses PBKDF2HMAC with SHA-256 for key derivation and Fernet for symmetric encryption.

---

## ✨ Features
- Encrypt and decrypt any text with a numeric password.
- Password is internally transformed into multiple derived keys for stronger security.
- Easy-to-use **command-line interface**.
- Error handling for wrong passwords or invalid text.

⚠️ **Note:** Only numeric passwords are allowed.

---

## 🚀 Installation & Usage

1. Install Python 3 (if not already installed).
2. Install required dependencies:
   ```bash
   pip install cryptography
to run it: 
   ```bash
   python simple-text-encryption.py
