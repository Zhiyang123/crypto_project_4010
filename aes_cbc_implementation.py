#!/usr/bin/env python3
import sys,os
import Crypto
from Crypto.Cipher import AES
from settings import *
mode = AES.MODE_CBC

# PKCS7 padding: adding b bytes each worth b 
def padding(text):
    b = NUM_BYTES - (len(text) % NUM_BYTES)
    return text + chr(b)*b # PKCS7 padding

def unpadding(data):
    return data[:-data[-1]]


# AES CBC Encryption
def encryption(text):
    encryptor = AES.new(key.encode('utf-8'), mode,IV=IV.encode('utf-8'))
    padded_text = padding(text)
    return encryptor.encrypt(padded_text.encode('utf-8'))

# AES CBC decryption without padding
def decryption(encrypted):
    decryptor = AES.new(key.encode('utf-8'), mode, IV=IV.encode('utf-8'))
    return decryptor.decrypt(encrypted)

#### Script ####

usage = """
Usage:
  python3 aes_cbc_implementation.py <message>         encrypts and displays the message (output in hex format)
  python3 aes_cbc_implementation.py -d <hex code>      decrypts and displays the message

Cryptographic parameters can be changed in settings.py
"""
if __name__ == '__main__':
    if len(sys.argv) == 2 : 
        print(encryption(sys.argv[1]).hex())
    elif len(sys.argv) == 3 and sys.argv[1] == '-d' : 
        print(unpadding(decryption(bytes.fromhex(sys.argv[2]))))
    else:
        print(usage)