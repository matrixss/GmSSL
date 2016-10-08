## Pairing

We use a standalone module `pairing` to implement the cryptographic pairing operations. We also put some of the pairing-based schemes into the `pairing module`. Current the only reason is that Library number in `err` module seems to be limited.

One challenge of pairing is that pairing can be constructed over different types of elliptic curves, especially for non-supersingular curves. It seems hard to extend the current `ec` module to support curves over extension fields. But it is possible  because `ec` module use different files to implement operations over different fields. What we need to do  is to present extension field elements in `BIGNUM`. This needs some encoding/decoding between extension field element and integer.

The first step is to implement supersingular curve. So we can re-use the elliptic curve operations over the prime field in the `ec` module.