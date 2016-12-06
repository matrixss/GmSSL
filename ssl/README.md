



```
	SSL_CTX_use_certificate_chain_file
	SSL_CTX_use_public_parameters_file
	SSL_CTX_use_PrivateKey_file
```





 GM SSL VPN CipherSuites:
 from GM/T 0024-2014 Table 2

 1. `ECDHE_SM1_SM3`	{0xe0, 0x01}
 2. `ECC_SM1_SM3`	{0xe0, 0x03}
 3. `IBSDH_SM1_SM3`	{0xe0, 0x05}
 4. `IBC_SM1_SM3`	{0xe0, 0x07}
 5. `RSA_SM1_SM3`	{0xe0, 0x09}
 6. `RSA_SM1_SHA1`	{0xe0, 0x0a}
 7. `ECDHE_SM4_SM3`	{0xe0, 0x11}
 8. `ECC_SM4_SM3`	{0xe0, 0x13}
 9. `IBSDH_SM4_SM3`	{0xe0, 0x15}
10. `IBC_SM4_SM3`	{0xe0, 0x17}
11. `RSA_SM4_SM3`	{0xe0, 0x19}
12. `RSA_SM4_SHA`	{0xe0, 0x1a}

where the ECC and ECDHE should use SM2,
IBC and IBSDH should use SM9

Both `statem/statem_srvr.c:tls_construct_server_certificate` and
`statem/statem_clnt.c:tls_construct_client_certificate` use the
`ssl3_output_cert_chain` for the construction the certificate message. As
the GM SSL certificates will be dual-certificates or the public parameters
of when using identity-based crytography, we have to modify the function
`ssl_output_cert_chain` or just write another one. The state machine code
check the protocol version number to decide which function to use.

In

    enum {
        rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), ...
        ecdsa_sign(64), rsa_fixed_ecdh(65), ecdsa_fixed_ecdh(66),
        (255)
    } ClientCertificateType;

In TLS, both the client certificate and the server certificate share the
same `Certificate` structure, which is a opaque data of a list of ASN.1
certificates.

The GMSSL keeps the `rsa_sign(1)` and `ecdsa_sign(64)` of the
`ClientCertificateType`, and append a new type `ibc_params(80)`. The
semantic of `rsa_sign(1)` is preserved. But the `ecdsa_sign(64)` might have
been changed because it will be the `sm2_sign`.

When using the `ibc_params(80)`, the certificate list `Certificate` also been
changed into the PKG's identifier and the public parameters:

    opaque ASN.1IBCParam<1..2^24-1>;
    struct {
        opaque ibc_id<1..2^16-1>;
        ASN.1IBCParam ibc_parameter;
    } Certificate;

The `ibc_id` is just a opaque type, we can use just a printable string or a
X.509 distinguished name in the PKG's certificate. The `ibc_parameter` can
be the DER encoding of the `SM9PublicParameters`. If we need to use another
identity-based schemes such as BF-IBE or CPK, we can append enum values of
the `ClientCertificateType`.

In the code, we can implement serveral similar functions of
`statem/statem_lib.c:ssl3_output_cert_chain`, such as `gmssl1_output_dualcert`
and `gmssl1_output_sm9params`.



Server Certificate
------------------


The server should always send the `Certificate` message to the client.

When using RSA, ECC or ECDHE, the certificate list should be the
dual-certificats, server's signature certificate and encryption
certificate. The specification did not mention if the certificate-chain
can also be sent. For typical VPN applications, the root certificates
should be deployed beforehand, so the chain will not be so necessary.

In RFC 5246:
   This is a sequence (chain) of certificates.  The sender's
   certificate MUST come first in the list.  Each following
   certificate MUST directly certify the one preceding it.

When using IBC or IBSDH, the content of this message shoulld be the
server's identity and the IBC public parameters.

opaque ASN.1IBCParam<1..2^24-1>;
struct {
      opaque ibc_id<1..2^16-1>;
     ASN.1IBCParam ibc_parameter;
 } Certificate;


	enum {
		rsa,
	}

In TLS, the server will NOT always send `ServerKeyExchange`. When the
server's certificate has an encryption public key, the client and server
will not run the Diffie-Hellman, only the client need to send the key
exchange message with the encrypted pre-master-secret. But in GMSSL, the
server must always send `ServerKeyExchange`.

The `ECParameters` in [RFC 4492]:

```
        struct {
            ECCurveType    curve_type;
            select (curve_type) {
                case explicit_prime:
                    opaque      prime_p <1..2^8-1>;
                    ECCurve     curve;
                    ECPoint     base;
                    opaque      order <1..2^8-1>;
                    opaque      cofactor <1..2^8-1>;
                case explicit_char2:
                    uint16      m;
                    ECBasisType basis;
                    select (basis) {
                        case ec_trinomial:
                            opaque  k <1..2^8-1>;
                        case ec_pentanomial:
                            opaque  k1 <1..2^8-1>;
                            opaque  k2 <1..2^8-1>;
                            opaque  k3 <1..2^8-1>;
                    };
                    ECCurve     curve;
                    ECPoint     base;
                    opaque      order <1..2^8-1>;
                    opaque      cofactor <1..2^8-1>;
                case named_curve:
                    NamedCurve namedcurve;
            };
        } ECParameters;

        struct {
            ECParameters    curve_params;
            ECPoint         public;
        } ServerECDHParams;

        select (KeyExchangeAlgorithm) {
            case ec_diffie_hellman:
                ServerECDHParams    params;
                Signature           signed_params;
        } ServerKeyExchange;

          enum { ecdsa } SignatureAlgorithm;

          select (SignatureAlgorithm) {
              case ecdsa:
                  digitally-signed struct {
                      opaque sha_hash[sha_size];
                  };
          } Signature;
```

The `ServerECDHEParams` in [GM/T 0024-2014]:

        struct {
            ECParameters curve_params;
            ECPoint public;
        } ServerECDHEParams;


For GmSSL, normally we will use the named curve `sm2p256v1`.




opaque ASN.1Cert<1..2^24-1>;

      struct {
          ASN.1Cert certificate_list<0..2^24-1>;
      } Certificate;


    opaque ASN.1IBCParam<1..2^24-1>;

    struct {
        opaque ibc_id<1..2^16-1>;
        ASN.1IBCParam ibc_parameter;
    } Certificate;




/* Server Key Exchange Message


    enum { ECDHE, ECC, IBSDH, IBC, RSA
    } KeyExchangeAlgorithm;

    struct {

    select ECDHE:
        ServerECDHEParams params;
        digitally-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            ServerECDHEParams params;
        } signed_params;

    case ECC:
        digitally-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            opaque ASN.1Cert<1..2^24-1>;
        } signed_params;

    case IBSDH:
        ServerIBSDHParams params;
        digitially-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            ServerIBSDHParams params;
        } signed_params;

    case IBC:
        ServerIBCParams params;
        digitially-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            ServerIBCParams params;
            opaque IBCEncryptionKey[1024];
        } signed_params;

    case RSA:
        digitially-signed struct {
            opaque client_random[32];
            opaque server_random[32];
            opaque ASN.1Cert<1..2^24-1>;
        } signed_params;

    } ServerKeyExchange;


a) ServerECDHEParams:




b) ServerIBSDHParams:

 */



/*

 Certificate Request Message
 * The server can optionally send this message to the client.

    enum { rsa_sign(1) } ClientCertificateType;

    struct {
        ClientCertificateType certificate_types<1..2^8-1>;
        SignatureAndHashAlgorithm supported_signature_algorithms<2^16-1>;
        DistinguishedName certificate_authorities<0..2^16-1>;
    } CertificateRequest;


 There are some difference between GM/T and RFC: While in GM/T 0024, the
 `supported_signature_algorithms` attribute is missing.

    enum {
        rsa_sign(1), ecdsa_sign(64), ibc_params(80), (255)
    } ClientCertificateType;

    struct {
        ClientCertificateType certificate_types<1..2^8-1>;
        DistinguishedName certificate_authorities<0..2^16-1>;
    } CertificateRequest;


 The TLS requires the server to send the signing/digest algorithm pairs it
 supports in the `CertificateRequest` message, but GM SSL 1.1 assumes that
 the server supports all the algorithms in a limited set, so the
 `supported_signature_algorithms` attribute is removed.

 The `certificate_authorities` is the list of DN names of the CAs. When the
 requested certificate type is `ibc_params(80)`, it should be the name list
 of the trusted domains defined by the PKG, for example, a list of the
 trusted email servers' domain names.



 `ClientKeyExchange` Message

    struct {
        select (KeyExchangeAlgorithm) {
        case ECDHE:
            opaque CientECDHEParams<1..2^16-1>;
        case IBSDH:
            opaque CientIBSDHParams<1..2^16-1>;
        case ECC:
            opaque ECCEncryptedPreMasterSecret<0..2^16-1>;
        case IBC:
            opaque IBCEncryptedPreMasterSecret<0..2^16-1>;
        case RSA:
            opaque RSAEncryptPreMasterSecret<0..2^16-1>;
        } exchange_keys;
    } ClientKeyExchange;

ClientECDHEParams:

    struct {
        ECParameters curve_params;
        ECPoint public;
    } ClientECDHEParams;

If the protocol is configured to use SM2 and the recommended `sm2p256v1`
curve, the `curve_params` should be the default value, the implementation
can check it, or just omit it as the GM/T 0024 suggested.


The `ClientIBSDHParams` is introduced in SM9 documents.

