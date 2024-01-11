from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def AES_CBC_encrypt(plaintext, AES_key, initialization_vector):
    """
    Encrypts the plaintext using AES-CBC encryption mode.
    
    Args:
        plaintext (bytes): The plaintext to be encrypted.
        AES_key (bytes): The AES key used for encryption.
        initialization_vector (bytes): The initialization vector used for encryption.
    
    Returns:
        bytes: The ciphertext generated from the encryption process.
    """
    AES_CBC_cipher = AES.new(AES_key, AES.MODE_CBC, iv=initialization_vector)
    ciphertext = AES_CBC_cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def AES_CBC_decrypt(ciphertext, AES_key, initialization_vector):
    """
    Decrypts the ciphertext using AES-CBC decryption mode.
    
    Args:
        ciphertext (bytes): The ciphertext to be decrypted.
        AES_key (bytes): The AES key used for decryption.
        initialization_vector (bytes): The initialization vector used for decryption.
    
    Returns:
        bytes: The decrypted plaintext.
    """
    AES_CBC_cipher = AES.new(AES_key, AES.MODE_CBC, iv=initialization_vector)
    decrypted_plaintext = unpad(AES_CBC_cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_plaintext

plaintext = input("Enter the plaintext: ").encode("ASCII")

AES_key = get_random_bytes(16)

initialization_vector = get_random_bytes(16)

ciphertext = AES_CBC_encrypt(plaintext, AES_key, initialization_vector)

decrypted_plaintext = AES_CBC_decrypt(ciphertext, AES_key, initialization_vector)

print("Plaintext: ", plaintext.decode("ASCII"))
print("Ciphertext: ", ciphertext.hex())
print("Decrypted plaintext: ", decrypted_plaintext.decode("ASCII"))
