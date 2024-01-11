from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def AES_GCM_encrypt(plaintext, AES_key, nonce):
    """
    Encrypts the plaintext using AES-GCM encryption.
    
    Args:
        plaintext (bytes): The plaintext to be encrypted.
        AES_key (bytes): The AES key used for encryption.
        nonce (bytes): The nonce used for encryption.
        
    Returns:
        bytes: The ciphertext generated from the encryption.
    """
    AES_GCM_cipher = AES.new(AES_key, AES.MODE_GCM, nonce=nonce)
    ciphertext = AES_GCM_cipher.encrypt(plaintext)
    return ciphertext

def AES_GCM_decrypt(ciphertext, AES_key, nonce):
    """
    Decrypts the ciphertext using AES-GCM decryption.
    
    Args:
        ciphertext (bytes): The ciphertext to be decrypted.
        AES_key (bytes): The AES key used for decryption.
        nonce (bytes): The nonce used for decryption.
        
    Returns:
        bytes: The decrypted plaintext.
    """
    AES_GCM_cipher = AES.new(AES_key, AES.MODE_GCM, nonce=nonce)
    decrypted_plaintext = AES_GCM_cipher.decrypt(ciphertext)
    return decrypted_plaintext

# Get the plaintext from user input
plaintext = input("Enter the plaintext: ").encode("ASCII")

# Generate a random AES key
AES_key = get_random_bytes(16)

# Generate a random nonce
nonce = get_random_bytes(16)

# Encrypt the plaintext using AES-GCM encryption
ciphertext = AES_GCM_encrypt(plaintext, AES_key, nonce)

# Decrypt the ciphertext using AES-GCM decryption
decrypted_plaintext = AES_GCM_decrypt(ciphertext, AES_key, nonce)

# Print the results
print("Plaintext: ", plaintext.decode("ASCII"))
print("Ciphertext: ", ciphertext.hex())
print("Decrypted plaintext: ", decrypted_plaintext.decode("ASCII"))
