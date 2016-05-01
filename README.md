# JCPasswordManager
JavaCard Password Manager is a java applet used to create and securely store a strong password used with the steganography app created by arunenigma (https://github.com/arunenigma/Steganography-Java-GUI). 

Arunenigma's application will be modified in a way, that it automatically communicates with an available JavaCard to retrieve the neccesary password for encryption/decrytion purposes. 

Access to the card is protected with a user PIN. This PIN cannot be brute-forced as the card will lock itself after 3 unsuccessful attempts. A locked card can be unlocked with an admin PIN, which is set when the applet is registered on the card. In case the admin PIN is entered wrong 3 times in a row, the card applet is blocked for good.    

This project is created within the PV204 (Security Technologies) course on FI MUNI.

# Installation

```
gp.exe --install stegopassapplet.cap --param 0C041000000000000000000000000000000000FC065A4ABA57A1C29BBB107D5FE6DE32 --verbose --debug --default
```

Installation data format is (hex format):

```
| ADMIN_PIN_LENGTH | USER_PIN_LENGTH | AES_KEY_LENGTH | ADMIN_PIN        | USER_PIN        | AES_KEY
| 1 BYTE           | 1 BYTE          | 1 BYTE         | ADMIN_PIN_LENGTH | USER_PIN_LENGTH | AES_KEY
```

The Stego application is looking for the pre-shared key in a KeyStore "store.ks" in the root folder. A store can be easily generated using the keytool:

```
keytool.exe -genseckey -alias SecureChannelPSK -keyalg AES -keysize 128 -storepass KS0000 -storetype JCEKS -keystore store.ksY
```

***Note*** that store password (and key password within store) has to be "KSXXXX" where XXXX is the default PIN used in the applet installation parameters. In case the end user is chaning his PIN, the KeyStore PIN is changed accordinglly automaticaly. 
