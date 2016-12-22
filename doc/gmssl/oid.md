# OIDs

<!-- What is OID. -->

The standard GM/T 0006-2012 _Cryptographic Application Identifier Criterion Specification_ defines a collection of OIDs, listed in the following table. While this collect lacks many OIDs required by typical applications, such as the combination of block cipher with operation modes. The GmSSL follows the GM/T 0006 specification and add more OIDs if required. see `crypto/objects/objects.txt` for more details.


| OID                   | NAME                              |
| --------------------- | --------------------------------- |
| 1.2                   | ISO                               |
| 1.2.156               | China                             |
| 1.2.156.197           | OSCCA                             |
| 1.2.156.10197         | GM Standard Committee             |
| 1.2.156.10197.1       | Cryptographic Algorithm           |
| 1.2.156.10197.1.100   | Block Cipher                      |
| 1.2.156.10197.1.102   | SM1 Block Cipher                  |
| 1.2.156.10197.1.103   | SSF33 Block Cipher                |
| 1.2.156.10197.1.104   | SM4 Block Cipher                  |
| 1.2.156.10197.1.200   | Stream Cipher                     |
| 1.2.156.10197.1.201   | ZUC Stream Cipher                 |
| 1.2.156.10197.1.300   | Public Key Cryptography           |
| 1.2.156.10197.1.301   | SM2 Elliptic Curve Cryptography   |
| 1.2.156.10197.1.301.1 | SM2-1 Digital Siganture Algorithm |
| 1.2.156.10197.1.301.2 | SM2-2 Key Exchange Protocol       |
| 1.2.156.10197.1.301.3 | SM2-3 Public Key Encryption       |
| 1.2.156.10197.1.302   | SM9 Identity-Based Cryptography   |
| 1.2.156.10197.1.302.1 | SM9-1 Digital Signature Algorithm |
| 1.2.156.10197.1.302.2 | SM9-2 Key Exchange Protocol       |
| 1.2.156.10197.1.302.3 | SM9-3 Public Key Encryptio        |
| 1.2.156.10197.1.400   | Hash Algorithm                    |
| 1.2.156.10197.1.401   | SM3 Hash Algorithm                |
| 1.2.156.10197.1.401.1 | SM3 Hash Without Key              |
| 1.2.156.10197.1.401.2 | SM3 Hash With Key                 |
| 1.2.156.10197.1.500   | Digest Signing                    |
| 1.2.156.10197.1.501   | SM2 Signing with SM3              |
| 1.2.156.10197.1.504   | RSA Signing with SM3              |
| 1.2.156.10197.4.3     | Certificate Authority             |
| 1.2.156.10197.6       | Standard Class                    |
| 1.2.156.10197.6.1     | Fundatation Class                 |
| 1.2.156.10197.6.1.1   | Algorithm Class                   |
| 1.2.156.10197.6.1.1.1 | ZUC Standard                      |
| 1.2.156.10197.6.1.1.2 | SM4 Standard                      |
| 1.2.156.10197.6.1.1.3 | SM2 Standard                      |
| 1.2.156.10197.6.1.1.4 | SM3 Standard                      |
| 1.2.156.10197.6.1.2   | ID Class                          |
| 1.2.156.10197.6.1.2.1 | Crypto ID                         |
| 1.2.156.10197.6.1.3   | Operation Modes                   |
| 1.2.156.10197.6.1.4   | Security Mechanism                |
| 1.2.156.10197.6.1.4.1 | SM2 Specificate                   |
| 1.2.156.10197.6.1.4.2 | SM2 Cryptographic Message Syntax  |
| 1.2.156.10197.6.2     | Device Class                      |
| 1.2.156.10197.6.3     | Service Class                     |
| 1.2.156.10197.6.4     | Infrastructure                    |
| 1.2.156.10197.6.5     | Testing Class                     |
| 1.2.156.10197.6.5.1   | Random Testing Class              |
| 1.2.156.10197.6.6     | Management Class                  |

------------------------------------------------------
Copyright 2016 The GmSSL Project. All Rights Reserved.
