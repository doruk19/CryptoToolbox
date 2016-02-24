# CryptoToolbox
Welcome to Cryptotoolbox!
This is a simple package I created while back when I was doing my cryptography term project.

It does not hold any practical purpose but it is a good reference to understand various encryption, digital signature and hashing algorithms.
You can freely change contents.

Supported algorithms & keysizes:

RSAOAEP Encryption with 1024-bit,2048-bit or 3072-bit key; 
El Gamal Encryption with 1024-bit,2048-bit or 3072-bit key;
AES;
Triple-DES; 
SHA-256, SHA-384 and SHA-512 hashing; 
DSA Digital Signature with 1024-bit,2048-bit or 3072-bit key; 
RSAPSS Digital Signature with 1024-bit,2048-bit or 3072-bit key.

Notes:
For algorithms requiring large primes, primes are generated with Miller-Rabin Primality Test.
Block cipher and hashing algorithms were not the main concern of the project, therefore these use built-in functions of Java.
