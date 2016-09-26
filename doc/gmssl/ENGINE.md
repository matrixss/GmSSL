## GmSSL Engines

GmSSL use ENGINEs to support cryptographic hardwares such as PCI-E cryptographic
card or USB Key from vendors. As currently there are two different APIs for
cryptographic hardwares in GM standards, the SKF API [1] and the SDF API [2],
the GmSSL project provides two ENGINEs, the SKF ENGINE and the SDF ENGINE to
support hardware with different APIs.


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

### Reference

 1. GM/T 0016-2012 Smart Card and Smart Token Cryptography Application Interface
    Specification
 2. GM/T 0018-2012 Interface Specifications of Cryptography Device Application.
 3. GM/T 0019-2012 Universal Cryptography Service Interface Specification.
