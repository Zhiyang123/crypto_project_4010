# TODO: Sending a response like "Valid padding" or "Invalid padding" rather than just boolean value


#!/usr/bin/env python3
import sys,os
from Crypto.Cipher import AES
from settings import *
mode = AES.MODE_CBC

# AES CBC decryption 
def decryption(encrypted):
    # decryptor = AES.new(key, mode, IV=IV)
    # TODO: Have to encode the key and IV to byte before passing into AES encrytion object
    decryptor = AES.new(key.encode('utf-8'), mode,IV=IV.encode('utf-8'))
    return decryptor.decrypt(encrypted)


# Ckeck validity of PKCS7 padding
def pkcs7_padding(data):
    pkcs7 = True
    last_byte_padding = data[-1]
    if(last_byte_padding < 1 or last_byte_padding > 16):
      pkcs7 = False
      message = "Invalid padding because {} is out of range (correct range: 1-16)".format(last_byte_padding)
    else:
      for i in range(0,last_byte_padding):
        if(last_byte_padding != data[-1-i]):
          pkcs7 = False
          message = "Invalid padding {} is supposed to be this value, {}".format(data[-1-i], last_byte_padding)
          break
        else:
          message = "Valid padding {} is {}.\n".format(data[-1-i], last_byte_padding)
    return pkcs7, message

# Determine if the message is encrypted with valid PKCS7 padding
def oracle_test(encrypted):
    return pkcs7_padding(decryption(encrypted))

