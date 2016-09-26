# GmSSL

GmSSL is a open source cryptography and SSL/TLS library forked from OpenSSL.
GmSSL support Chinese cryptography algorithms and standards.



Block Ciphers:

 * SM1
 * SSF33
 * SM4/SMS4
 * GM One-Time Password (OTP)
 * Combined Public Key (CPK)
 * Format-Preserve Encryption (FFX)
 * CBC-MAC (compatible with GM standards)

Block Cipher Operation Modes:

 * ECB, CBC, CFB, OFB, CTR.
 * CCM, GCM, OCB.
 * FFX.

Stream Ciphers:

 * ZUC
 * RC4

Hash Functions:

 * SM3
 * SHA-1, SHA-2
 * Blake2
 * MD5
 * MDC2

Key Derive Functions (KDF):

 * X9.63 KDF
 * IBCS (RFC 5094) KDF

MAC:

 * CBC-MAC
 * HMAC
 * CMAC
 * GMAC

Public Key Cryptography:

 * ECIES (Elliptic Curve Integrated Encryption Scheme)
 * SM2 Public Key Encryption
 * SM2 Key Agreemetn Protocol
 * SM2 Digital Signature Scheme
 * SM9 Identity-Based Encryption
 * SM9 Identity-Based Sigature Scheme
 * SM9 Identity-Based Key Agreement Protocol
 * Paillier Encryption with Addition Homomorphism
 * CPK (Combined Public Key)

SSL/TLS Protocols:

 * GM SSL VPN
 * TLS 1.3
 * TLS 1.0/1.1/1.2

Cryptographic APIs:

 * OpenSSL EVP (Envelop) API
 * GM SKF API and SDF API
 * Java API through JNI

Hardware Support:

 * GM Cryptographic Hardware SKF/SDF
 * VIA-Alliance SM3/SM4 Instructions
 * Intel AVX2 acceleration for SM4/SMS4


