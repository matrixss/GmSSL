## Engines

GmSSL use ENGINEs to support cryptographic hardwares such as PCI-E cryptographic
card or USB Key from vendors. As currently there are two different APIs for
cryptographic hardwares in GM standards, the SKF API [1] and the SDF API [2],
the GmSSL project provides two ENGINEs, the SKF ENGINE and the SDF ENGINE to support hardware with different APIs.


## Build

The following configure options:

* `no-engines`
* `enable-dynamic-engines`
* `enable-capieng`



### SKF ENGINE


### SDF ENGINE

Sansec [http://www.sansec.com.cn](http://www.sansec.com.cn) is a major vendor
for PCI-E cryptographic cards. The products from Sansec provides the SDF API.
So GmSSL can communicate with Sansec cards through the `SDF` ENGINE.

The initial version of the GmSSL SDF ENGINE will only support SM2 Signature
generation. The following SDF APIs will be used:

* `SDF_OpenDevice/CloseDevice`
* `SDF_OpenSession/CloseSession`
* `SDF_GetDeviceInfo`
* `SDF_ExportSignPublicKey_ECC`
* `SDF_GetPrivateKeyAccessRight/ReleasePrivateKeyAccessRight`
* `SDF_InternalSign_ECC`

Some features of the SDF API:

* You can not open a specific device if multiple devices co-exist in the same
   computer through the `SDF_OpenDevice()` function. This means there should be
   only one device equipped, or only the default device can be opened.
* The access control is fine-grained. The application need the coresponding
   password to access a key. And as a PCI-E card, a SDF device can store lots of
   keys, which means the application has to manage lots of passwords.
* The SDF API uses index (number) to access the key. No label or name is
   provided to simpify the key management. The application has to store the
   indexes and metadata of the keys it creates.
* The input of SM2 signature generate is the final digest, i.e. `H(Z||M)` where
   `M` is the message. See `SDF_InternalSign_ECC` in ref [1].


## Built-in Engines

* `capi` - Microsoft CryptoAPI Engine, optional
* `chil` - nCipher CHIL
* `dasync` - No install
* `ossltest` - OpenSSL example engine for testing, no install
* `padlock` - VIA PadLock
* `afalg` - Linux CryptoAPI with `AF_ALG` (netlink)
* `rdrand` - Intel `RDRAND` random number generation instruction.
* `cryptodev` - OpenBSD Cryptographic Framework (OCF) `/dev/crypto`.
* `openssl`

### `AF_ALG`
A netlink-based interface that adds an `AF_ALG` address family;[2] it was merged
into version 2.6.38 of the Linux kernel mainline.[3][4] There was once a plugin
to OpenSSL to support `AF_ALG`,[5] which has been submitted for merging.[6] In
version 1.1.0, OpenSSL landed another patch for `AF_ALG` contributed by Intel.

### RDRAND

If you are concerned over possible RDRAND tampering, then you should explicitly
call `RAND_set_rand_engine(NULL)` after loading all engines. If another module in
the program happens to call `ENGINE_load_builtin_engines` again, then you will go
back to using RDRAND.
You can also call `ENGINE_unregister_RAND` followed by
`ENGINE_register_all_complete` to unregister RDRAND as default random number
generator implementation.
To avoid accidental use of RDRAND, you can build OpenSSL with
`OPENSSL_NO_RDRAND`
defined. This is the preferred method to avoid all use of RDRAND.

`ENGINE_cleanup()`


### cryptodev

The OpenBSD Cryptographic Framework `/dev/crypto` interface of OpenBSD was ported
to Linux,[8][9][10] but never merged.

## Third-Party Engines

* `gost` (https://github.com/gost-engine/engine). Russian GOST crypto algorithms.
* `engine-pkcs11` (https://github.com/OpenSC/libp11). OpenSC PKCS #11 Engine.


### Reference

 1. GM/T 0016-2012 Smart Card and Smart Token Cryptography Application Interface
    Specification
 2. GM/T 0018-2012 Interface Specifications of Cryptography Device Application.
 3. GM/T 0019-2012 Universal Cryptography Service Interface Specification.
