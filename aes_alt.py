#!/usr/bin/env python3
import sys,os
import Crypto
from Crypto.Cipher import AES
from settings import *
import hmac, hashlib
mode = AES.MODE_CBC

def encrypt(plaintext, key, IV):
    # creating the AES cipher with the key, mode of AES (cbc), IV (initialization vector)
    # the key and IV would be encoded in 'utf-8' format
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, IV.encode('utf-8'))
    length = 16 - (len(plaintext) % 16)

    # the plaintext would be padded accordingly to PKCS #7
    plaintext += chr(length) * length

    # the ciphertext would be returned
    return cipher.encrypt(plaintext.encode('utf-8'))

def decrypt(ciphertext, key):
    # creating the AES cipher with the key, mode of AES (cbc), IV (initialization vector)
    # the key and IV would be encoded in 'utf-8' format
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, IV.encode('utf-8'))

    # the decrypted plaintext would consist of original message + padding
    plaintext = cipher.decrypt(ciphertext)

    # extracting the number of padding applied to the message
    padding_length = plaintext[-1]

    # returning only the original message
    return plaintext[:-padding_length]

def generate_HMAC(key, message):
    hash_function = hashlib.sha256
    mac = hmac.new(key.encode('utf-8'), message.encode('utf-8'), hash_function)
    return mac.digest()


if __name__ == '__main__':

    if len(sys.argv) == 3 and sys.argv[1] == 'encrypt':
        plaintext = sys.argv[2]
        ciphertext = encrypt(plaintext, key, IV)
        print(ciphertext.hex())
    elif len(sys.argv) == 3 and sys.argv[1] == 'HMAC':
        plaintext = sys.argv[2]
        HMAC = generate_HMAC(key, plaintext)
        plaintext = plaintext + str(HMAC)
        ciphertext = encrypt(plaintext, key, IV)
        print(ciphertext.hex())
        print(HMAC)
    elif len(sys.argv) == 3 and sys.argv[1] == 'decrypt':
        ciphertext = bytes.fromhex(sys.argv[2])
        plaintext = decrypt(ciphertext, key)
        print(plaintext.decode('utf-8'))
    else:
        print("Usage:")
        print("To encrypt: python aes_alt.py encrypt <message>")
        print("To decrypt: python aes_alt.py decrypt <ciphertext in hex>")
        print("To encrypt with HMAC: python aes_alt.py HMAC <message")
