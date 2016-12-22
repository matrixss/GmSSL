# Add New Sub-libraries

Most of the GmSSL new modules are implemented as the OpenSSL sub-libraries.
Normally each new crypto scheme is implemented as a standalone sub-libraries,
such as the SM3, SM4, SM9 and Paillier, some related schemes are packed into
one sub-library, such as the SM2 is packed into EC, and multiple pairing-based
schemes are packed into the pairing sub-library.

Given the new algorithm is Paillier, then the paillier sub-library has the following components:

* a folder in `crypto` with the same name of the algorithm, `crypto/paillier`.
   The source code and the build script is included.
* a header file in `include/openssl/` with the same name of the algorithm, i.e. `include/openssl/paillier.h`.
* a test file in `test` folder with the name as prefix, `test/pailliertest.c`.
* some modification on the `crypto/err` if error stack is require, see the
   OpenSSL err man page for more inforamtion.
* add the module to the major `Configure` file.

As the `Configure` file is changed, `./config` need to be run again. During the
developing of a new sub-library, `./make update` also need to be run multiple
times in case new functions or error codes are added.

You can see the `paillier` module as an example because it is a full-feature
sub-library with all the above modifications.

## Sub-libraries of GmSSL

| SuB-LIBRARY | Description                     |
| ----------- | ------------------------------- |
| `cbcmac`    | CBC-MAC                         |
| `cpk`       | CPK (Combined Public Key)       |
| `gmapi`     | GM API                          |
| `paillier`  | Paillier Cryptosystem           |
| `pairing`   | Bilinear Pairing                |
| `saf`       | SAF API                         |
| `sdf`       | SDF API                         |
| `skf`       | SKF API                         |
| `sm3`       | SM3 Digest Algorithm            |
| `sm9`       | SM9 Identity-based Cryptography |
| `sms4`      | SMS4 Block Cipher               |
| `sof`       | SOF API                         |
| `zuc`       | ZUC Stream Cipher               |
|             |                                 |
|             |                                 |
|             |                                 |
|             |                                 |
|             |                                 |
|             |                                 |

