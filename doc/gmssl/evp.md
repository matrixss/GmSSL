
SM2 EVP_PKEY_METHOD
-------------------

The current version of OpenSSL (1.1.0) does not support public key encryption
schemes of elliptic curve cryptography. Infect, the only provided public key
encryption scheme is RSA. While in GmSSL both the ECIES (Elliptic Curve
Integrated Encryption Scheme) and the SM2 public key encryption scheme are
supported. As the ECIES and SM2 encryption both use the `EC_KEY` type as the key
type, these two schemes can be seen as different implementations of the
`EVP_PKEY_EC` type.

If there are no extra data in the `EC_KEY` object that can be used to select
between the international scheme and the Chinese SM2 scheme, the caller can set
the scheme through the `EVP_PKEY_CTX_ctrl()` interface.



If we want to adjust the default behavior of a `EVP_PKEY` related operation,
there are two places for us to do that:

 * put the adjustment into the `EVP_PKEY` object
 * adjust through the `EVP_PKEY_CTX`, this can be done by `EVP_PKEY_CTX_ctrl()`
   operations.

