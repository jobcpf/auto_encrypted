"""
Cryptography Script.

Encrypt and Decrypt using padded keys.

@Author: https://stackoverflow.com/users/810918/101100
@Date: 2011-06-24

ref: https://stackoverflow.com/questions/6425131/encrypt-decrypt-data-in-python-with-salt

"""

################## Packages #################################### Packages #################################### Variables ##################

# Standard import
import Crypto.Random
from Crypto.Cipher import AES
import hashlib

################## Variables #################################### Variables #################################### Variables ##################

SALT_SIZE = 16 # salt size in bytes
NUMBER_OF_ITERATIONS = 20 # number of iterations in the key generation
AES_MULTIPLE = 16 # the size multiple required for AES

################## Functions ###################################### Functions ###################################### Functions ####################

def generate_key(password, salt, iterations):
    assert iterations > 0, "Iterations must be above 0"

    key = password + salt

    for i in range(iterations):
        key = hashlib.sha256(key).digest()  

    return key


def pad_text(text, multiple):
    extra_bytes = len(text) % multiple

    padding_size = multiple - extra_bytes

    padding = chr(padding_size) * padding_size

    padded_text = text + padding

    return padded_text


def unpad_text(padded_text):
    padding_size = ord(padded_text[-1])

    text = padded_text[:-padding_size]

    return text


def encrypt(plaintext, password):
    salt = Crypto.Random.get_random_bytes(SALT_SIZE)

    key = generate_key(password, salt, NUMBER_OF_ITERATIONS)

    cipher = AES.new(key, AES.MODE_ECB)

    padded_plaintext = pad_text(plaintext, AES_MULTIPLE)

    ciphertext = cipher.encrypt(padded_plaintext)

    ciphertext_with_salt = salt + ciphertext

    return ciphertext_with_salt


def decrypt(ciphertext, password):
    salt = ciphertext[0:SALT_SIZE]

    ciphertext_sans_salt = ciphertext[SALT_SIZE:]

    key = generate_key(password, salt, NUMBER_OF_ITERATIONS)

    cipher = AES.new(key, AES.MODE_ECB)

    padded_plaintext = cipher.decrypt(ciphertext_sans_salt)

    plaintext = unpad_text(padded_plaintext)

    return plaintext