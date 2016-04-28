# JCPasswordManager
JavaCard Password Manager is a java applet used to create and securely store a strong password used with the steganography app created by arunenigma (https://github.com/arunenigma/Steganography-Java-GUI). 

Arunenigma's application will be modified in a way, that it automatically communicates with an available JavaCard to retrieve the neccesary password for encryption/decrytion purposes. 

Access to the card is protected with a user PIN. This PIN cannot be brute-forced as the card will lock itself after 3 unsuccessful attempts. A locked card can be unlocked with an admin PIN, which is set when the applet is registered on the card. In case the admin PIN is entered wrong 3 times in a row, the card applet is blocked for good.    

This project is created within the PV204 (Security Technologies) course on FI MUNI.

# Installation

```
gp --install stegopassapplet.cap --param 0C040102030405060708090A0B0C01020304 --verbose --default
```

Input data format is (hex format):

```
| ADMIN_PIN_LENGTH | USER_PIN_LENGTH | ADMIN_PIN        | USER_PIN        |
| 1 BYTE           | 1 BYTE          | ADMIN_PIN_LENGTH | USER_PIN_LENGTH |
```
