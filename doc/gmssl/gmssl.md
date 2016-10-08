



When adding ECIES, SM2, Pairing and SM9, we need to add code to existing OpenSSL modules such as `bn` and `ec`. To reduce the difficulty of future merging into future version of OpenSSL, we make the new code in standalone source files if possible. And we separate interfaces into small header files. We prefer to add new functions into the modules these functions logically belong, instead of put these functions together with the callers. For example, to support pairing, we add new functions to `bn` and `ec`, and we put all the key derive functions (KDF) together to the `pdf` module.

