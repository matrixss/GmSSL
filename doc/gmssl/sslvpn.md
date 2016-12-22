# GM/T 0024 SSL VPN Specification

The differences between GM/T 0024 and TLS 1.1 and TLS 1.2:



## Version

The 2-byte version number of SSL/TLS protocol is used in the record layer and the handshake messages. It is composed of two octets, the major version and the minor number. For the ClientHello message, in the recorder layer only the major version number should be considered by the server. So the server can accept the first records with any minor version number, only to check if the major version number is acceptable. But normally the client should sent the ClientHello message with recode layer minor version to be zero. And the handshake ClientHello message version number to the values the Client prefers.

The current version of GM SSL is 1.1 (0x01, 0x01), different from SSL 2.0 (0x02, 0x00), SSL 3.0 (0x03, 0x00), TLS 1.0 (0x03, 0x01), TLS 1.1 (0x03, 0x02), TLS 1.2 (0x03, 0x03), and the future TLS versions.

The advantage of GM SSL set the version to be 1.1 is that it will not conflict with the future SSL/TLS versions.

## Cipher Suite Naming

There are different naming of SSL/TLS cipher suites:

* Naming in RFCs, for example `TLS_RSA_WITH_AES_128_CBC_SHA256`
* OpenSSL Naming, `"RSA_WITH_AES_128_SHA256"`
* GM SSL Naming `RSA_SM1_SHA1`

The OpenSSL cipher suite text names remove the prefix TLS and the block cipher mode CBC. GM SSL follows the similar naming method of OpenSSL, removing all the constant values in the names.

### ECDHE

In SSL/TLS the ECDHE means ECDH with temporary public key. But in GM SSL it is not. It has the same meaning of ECDH.

### ECC

In SSL/TLS, only the RSA (through RSA encryption key certificate) can be used for key transfer. ECIES and DHIES are not adopted in the TLS cipher suites. And in the future version of TLS the RSA key transfer method will also be removed.

The ECC in the GM SSL cipher suites means it use ECC encryption public key certificate as RSA.



## New Ciphers and Hash Algorithms

The GM SSL cipher suites use two new block ciphers, SM1 and SM4, and one new hash algorithm SM3.

No stream ciphers are used.

Only CBC mode of these two block ciphers are supported.



## Encryption

The SSL/TLS protocols support 3 types of bulk data encryption:

* `stream` stream cipher
* `block` block cipher with CBC mode
* `aead` AEAD modes including GCM and CCM

The GM SSL 1.1 only support the `block` method. As TLS 1.1, GM SSL 1.1 use padding, MAC then encrypt, with explicit IV for every record.

## PRF

In TLS 1.1, the PRF algorithm is fixed, using combination of MD5/SHA1. In TLS 1.2, for all the old cipher suites, the PRF algorithm is changed and based on SHA256. This new algorithm is called `tls_prf_sha256`. In this new cipher suites defined after TLS 1.2, the cipher suites will explicitly define the PRF algorithm to be used. But as I know, all these cipher suites still use `tls_prf_sha256`.

GM SSL does not follow the algorithm in TLS 1.1, but follow the algorithm defined in TLS 1.2. Which is very similar to `tls_prf_sha256` but replace the hash algorithm to SM3. So we can call this PRF algorithm `tls_prf_sm3`.



## Signature Algorithm 

In TLS 1.1 when signing a message, the hash values are generated with the combination of MD5/SHA1. This means that in the TLS 1.1, only the public key in the signing key certificate is used. The hash algorithm defined in the certificated might not be used.

In TLS 1.2 the signing algorithm is exchange with the extension. And the signing will use the same hash algorithm defined in the certificate.

In GM SSL 1.1, the signing algorithm follows the TLS 1.2. But as GM SSL 1.1 cipher suites only support two hash algorithms, SM3 and SHA1.



## Extensions

Start from TLSv1.1 the SSL/TLS protocol starts to support extensions. The client can send his preferred extension list at the suffix of the ClientHello message (after the compress algorithm) to the server. If the server adopt any one of these extensions, it will send the extension id numbers back to the client through the ServerHello message. 

The GM SSL protocol does not support extensions.

It is NOT clear that if the client send the extensions in ClientHello, what should the server react. Send alerts or just ignore them.

Extensions have different purpose, enhancing functionality, performance and security. Some of the extensions such as elliptic curves and signing algorithms, in GM SSL it is fixed. So theses extensions are not useful in GM SSL. But the other extensions are important for performance and security, should be supported.



## Protocols on Record Layer

The SSL/TLS support 3 types of sub-protocols over the record layer:

* Handshake
* Alert
* ChangeCipherSpec
* Application Data

The GM SSL add a new one:

* Site2site

As the site2site protocol is only used in SSL VPN application scenarios, so we will not discuss this.

## MAC

GM SSL 1.1 only support HMAC-SHA1 and HMAC-SM3.

GM SSL 1.1 does not support the `truncated_hmac` extension. This means the MAC length is the digest length of the corresponding hash algorithms.



## Working Keys 

As GM SSL 1.1 use explicit IVs, and always use the block cipher with CBC mode and HMAC, so there are total 4 keys derived from the master secret. As all the encryption key length are 16-byte, the HMAC-SHA1 key length is 20-byte and the HMAC-SM3 key length is 32-byte, so the total key lengths are 72 bytes or 96 bytes.

## Alerts

GM SSL 1.1 keeps all the alert numbers of TLS 1.1, but add more alert values for its `site2site` protocol.

## Certificates

In GM SSL, the certificates are always 2, the signing certificate first, and then the encryption certificate.

The GM SSL specification did not mention if the certificate chain need to be send follows the second encryption certificate. There are several possibles if the chain is also send.

Some figures here ...

Some user will send the same certificate for both signing and verification. The GM specification did not mention it is legal or not.

## Cert Request

In GM SSL the CertRequest is optional. But in SM2 key exchange.



## Server Key Exchange



