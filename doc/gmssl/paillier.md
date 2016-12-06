# Paillier in GmSSL


The Paillier is an efficient public key encrypiton scheme with additive
homomorphism. The additive homomorphism capability makes Paillier a very
popular public key encryption scheme for outsourcing data encryption, secure
multi-party computation and a lot of security protocols. The performance of
Paillier is close to typical public key encryption schemes such as RSA and
ECIES, which makes it a much more practical choice than the fully homomorphic
encryption schemes. So GmSSL project provides the Paillier cryptosystem.


## Paillier Public Key Encryption

As a public key encryption scheme the Paillier has the following algorithms:

1. Key pair generation

	(pk, sk) = setup(k)

given key length in bits `k`, generate key pair `(pk, sk)`, where `pk` is the
public key and the `sk` is the private key.

2. Encryption

	c = encrypt(m, pk)

encrypt message `m` with public key `pk`, output ciphertext `c`.

3. Decryption

	m_ = decrypt(c, sk)

decrypt ciphertext `c` with private key `sk` and output plaintext `m_`. If the
`(pk, sk)` is a valid key pair, then `m_` should be equal to `m`, i.e.

	decrypt(encrypt(m, pk), sk) == m

The additive homomorphism of Paillier provides an estra algorithm, the
ciphertext additon `add()` over two ciphertext

	c1 = encrypt(m1, pk)
	c2 = encrypt(m2, pk)
	c3 = add(c1, c2, pk)

	decrypt(c3, sk) == c1 + c2

When multiple additions over the same ciphertext `c`, we call it scalar
multiplication. And we present the sum of `n` ciphertext `c` as:

	c + c + ... + c = c * n

We use function `mul()` to present this operation

	r = mul(c, n, pk)

where `n` is an integer in plaintext, and `r` is the sum of multiple `c`.


## Paillier Sub-library

The Paillier is provided with the public header file
`include/openssl/paillier.h` and the implementation is in the source folder
`crypto/paillier`.

The opapue object `PAILLIER` is used to present the Paillier key pair. So both
the public key and private key is included in the same data structure, just
like the `RSA`, `DSA` and `EC_KEY` data types.

The ASN.1/DER encoding/decoding funcations are also provided for the `PAILLIER`
data type with the standard `i2d_PAILLIER()` and `d2i_PAILLIER()` functions.

The plaintext of `paillier` is `BIGNUM`. But should be in the range of [1, N]
where N is the modulus of public key.

The ciphertext of `paillier` is also `BIGNUM`. So the `paililer` sub-library
does not provide any encoding/decoding functions for ciphertext and plaintext.


Following work on Paillier:

 1. Provide some functions to access the `PAILLIER` attributes
 2. Algorithm-level optimizations such as plaintext packing.
 3. Implementation-level optimizations.


