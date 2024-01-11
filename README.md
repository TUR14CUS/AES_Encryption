```markdown
# AES Encryption

This repository provides two Python scripts for implementing AES encryption using different modes: Cipher Block Chaining (CBC) and Galois/Counter Mode (GCM). The scripts utilize the pycryptodome library for cryptographic operations.

## AES_CBC.py

### Overview
The `AES_CBC.py` script demonstrates AES encryption and decryption in CBC mode. CBC is a block cipher mode that adds an Initialization Vector (IV) to each block before encryption. This script randomly generates an AES key and IV, takes user input for plaintext, and outputs the original plaintext, encrypted ciphertext, and decrypted plaintext.

### Usage
1. Run the script: `python AES_CBC.py`
2. Enter the plaintext when prompted.
3. The script generates a random AES key and IV.
4. Outputs the original plaintext, encrypted ciphertext, and decrypted plaintext.

## AES_GCM.py

### Overview
The `AES_GCM.py` script showcases AES encryption and decryption in GCM mode. GCM is an authenticated encryption mode that provides both confidentiality and integrity. This script generates a random AES key and nonce, takes user input for plaintext, and outputs the original plaintext, encrypted ciphertext, and decrypted plaintext.

### Usage
1. Run the script: `python AES_GCM.py`
2. Enter the plaintext when prompted.
3. The script generates a random AES key and nonce.
4. Outputs the original plaintext, encrypted ciphertext, and decrypted plaintext.

## Dependencies
- pycryptodome: Ensure you have the library installed before running the scripts. You can install it using `pip install pycryptodome`.

## Note
Feel free to use and modify these scripts for your projects. If you encounter any issues or have questions, refer to the pycryptodome documentation or create an issue in this repository.

For more information about AES encryption modes, you can explore additional resources such as the [NIST Recommendation for Block Cipher Modes of Operation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).
```
