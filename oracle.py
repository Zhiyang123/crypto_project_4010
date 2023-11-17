#!/usr/bin/env python3
import sys,os
from Crypto.Cipher import AES
from settings import *
import time
import hmac, hashlib
mode = AES.MODE_CBC

# AES CBC decryption 
def decryption(encrypted):
    # decryptor = AES.new(key, mode, IV=IV)
    # TODO: Have to encode the key and IV to byte before passing into AES encrytion object
    decryptor = AES.new(key.encode('utf-8'), mode,IV=IV.encode('utf-8'))
    return decryptor.decrypt(encrypted)

def generate_HMAC(key, message):
    hash_function = hashlib.sha256
    mac = hmac.new(key.encode('utf-8'), message, hash_function)
    return mac.digest()

def check_HMAC(given_HMAC, data):
    return given_HMAC == generate_HMAC(key, data)


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

# Ckeck validity of PKCS7 padding
def pkcs7_HMAC_padding(data, hmac):
    pkcs7 = True
    last_byte_padding = data[-1]
    if(last_byte_padding < 1 or last_byte_padding > 16):
      pkcs7 = False
      sent_message = "Invalid message"
      actual_message = "Invalid padding. {} not within 1 ~ 16.".format(last_byte_padding)
    else:
      for i in range(0,last_byte_padding):
        if(last_byte_padding != data[-1-i]):
          pkcs7 = False
          sent_message = "Invalid message"
          actual_message = "Invalid padding. Guess: {} Actual: {}.".format(data[-1-i], last_byte_padding)
          break
        else:
          sent_message = "Invalid message"
          actual_message = "Valid padding. Guess: {} Actual: {}.\n".format(data[-1-i], last_byte_padding)
    if (pkcs7 == True):
      time.sleep(0.02)
      if (check_HMAC(hmac, data[-1-i])):
        sent_message = "Valid message"
        actual_message = "Valid padding. Guess: {} Actual: {}. HMAC check .\n".format(data[-1-i], last_byte_padding)
      else:
        sent_message = "Invalid message"
        actual_message = "Valid padding. Guess: {} Actual: {}. HMAC check.\n".format(data[-1-i], last_byte_padding)
    return sent_message, actual_message

# Determine if the message is encrypted with valid PKCS7 padding
def oracle_test(encrypted):
    return pkcs7_padding(decryption(encrypted))

def oracle_HMAC_test(encrypted, hmac):
    return pkcs7_HMAC_padding(decryption(encrypted), hmac)
