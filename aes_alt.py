#!/usr/bin/env python3
import sys,os
import Crypto
from Crypto.Cipher import AES
from settings import *
mode = AES.MODE_CBC

def encrypt(plaintext, key, IV):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, IV.encode('utf-8'))
    length = 16 - (len(plaintext) % 16)
    plaintext += chr(length) * length
    return cipher.encrypt(plaintext.encode('utf-8'))

def decrypt(ciphertext, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, IV.encode('utf-8'))
    plaintext = cipher.decrypt(ciphertext)
    padding_length = plaintext[-1]
    return plaintext[:-padding_length]

if __name__ == '__main__':

    if len(sys.argv) == 3 and sys.argv[1] == 'encrypt':
        plaintext = sys.argv[2]
        ciphertext = encrypt(plaintext, key, IV)
        print(ciphertext.hex())
    elif len(sys.argv) == 3 and sys.argv[1] == 'decrypt':
        ciphertext = bytes.fromhex(sys.argv[2])
        plaintext = decrypt(ciphertext, key)
        print(plaintext.decode('utf-8'))
    else:
        print("Usage:")
        print("To encrypt: python aes_alt.py encrypt <message>")
        print("To decrypt: python aes_alt.py decrypt <ciphertext in hex>")
