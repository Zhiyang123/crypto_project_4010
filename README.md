**POODLE (or Padding Oracle Attack) Attack Exploitation Tool**

This tool exploits the POODLE vulnerability in SSLv3 and CBC cipher mode to decrypt and display encrypted messages.

**Usage**

* `python3 exploit.py <message>`: Decrypts and displays the message
* `python3 exploit.py HMAC <ciphertext> <HMAC>`: Decrypts and displays the message using HMAC
* `python3 exploit.py -o <hex code>`: Displays oracle answer
* `python3 exploit.py -h <number>`: Displays explanation for program (valid number: 0, 1)
* `python3 exploit.py -d <hex code>`: Displays logs

**Cryptographic Parameters**

* Can be changed in settings.py

**Note**

* This tool is for educational purposes only and should not be used for malicious activities.
