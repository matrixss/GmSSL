# SAF API

Different from normal cryptographic APIs such as the OpenSSL EVP API and the PKCS #11 Cryptoki API, the SAF API is not only a crypto API, but also provides routines for certificate management and PKCS #7 cryptographic message functionalities. These new features of the SAF API make the programmer easier for developing high level applications.

The GmSSL project provides the SAF API, which is the wrapping of GmSSL/OpenSSL native APIs. The code can be seen as examples of how to use the complicated native APIs. As the SAF API only consider simple situations without the support of streaming I/O, developers need to change to the native APIs if more control is required or higher performance when processing large data.
