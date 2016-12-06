## SM2


The SM2 schemes have some compatibility issues with the EVP API. These issues are coming from both the design of the EVP API and the specification of the SM2 standards.

In the SM2 signature scheme, not only the message digest is signed, but the digest of signer's identity information followed the message.

The EVP API provide two APIs to sign

EVP_SignInit/Update/Final

EVP_DigestSignInit/Update/Final.

H(H(ID||PUBKEY||CURVE) || H(M))

Instead of generation the signature of digest H(HID || M), the GmSSL generate the digest of H(HID || H(M)), this means that we will do one more call to the hash function.

