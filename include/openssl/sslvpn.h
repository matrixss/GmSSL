/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
/*
 * This header is based on the GM/T 0024-2014: SSL VPN Sepcification.
 */

#ifndef HEADER_GMSSL_H
#define HEADER_GMSSL_H


#ifdef __cplusplus
extern "C" {
#endif


#define GM1_VERSION		0x0101
#define GM1_VERSION_MAJOR	0x01
#define GM1_VERSION_MINOR	0x01


#define GM1_get_version(s) \
	((s->version >> 8) == GM1_VERSION_MAJOR ? s->version : 0)

#define GM1_get_client_version(s) \
	((s->client_version >> 8) == GM1_VERSION_MAJOR ? s->client_version : 0)


/* GM SSL VPN CipherSuites:
 * from GM/T 0024-2014 Table 2
 *
 *  1. ECDHE_SM1_SM3	{0xe0, 0x01}
 *  2. ECC_SM1_SM3	{0xe0, 0x03}
 *  3. IBSDH_SM1_SM3	{0xe0, 0x05}
 *  4. IBC_SM1_SM3	{0xe0, 0x07}
 *  5. RSA_SM1_SM3	{0xe0, 0x09}
 *  6. RSA_SM1_SHA1	{0xe0, 0x0a}
 *  7. ECDHE_SM4_SM3	{0xe0, 0x11}
 *  8. ECC_SM4_SM3	{0xe0, 0x13}
 *  9. IBSDH_SM4_SM3	{0xe0, 0x15}
 * 10. IBC_SM4_SM3	{0xe0, 0x17}
 * 11. RSA_SM4_SM3	{0xe0, 0x19}
 * 12. RSA_SM4_SHA1	{0xe0, 0x1a}
 *
 * where the ECC and ECDHE should use SM2,
 * IBC and IBSDH should use SM9
 */
#define GM1_CK_ECDHE_SM1_SM3		0x0300E001
#define GM1_CK_ECC_SM1_SM3		0x0300E003
#define GM1_CK_IBSDH_SM1_SM3		0x0300E005
#define GM1_CK_IBC_SM1_SM3		0x0300E007
#define GM1_CK_RSA_SM1_SM3		0x0300E009
#define GM1_CK_RSA_SM1_SHA1		0x0300E00A
#define GM1_CK_ECDHE_SM4_SM3		0x0300E011
#define GM1_CK_ECC_SM4_SM3		0x0300E013
#define GM1_CK_IBSDH_SM4_SM3		0x0300E015
#define GM1_CK_IBC_SM4_SM3		0x0300E017
#define GM1_CK_RSA_SM4_SM3		0x0300E019
#define GM1_CK_RSA_SM4_SHA1		0x0300E01A

#define GM1_TXT_ECDHE_SM1_SM3		"ECDHE-SM1-SM3"
#define GM1_TXT_ECC_SM1_SM3		"ECC-SM1-SM3"
#define GM1_TXT_IBSDH_SM1_SM3		"IBSDH-SM1-SM3"
#define GM1_TXT_IBC_SM1_SM3		"IBC-SM1-SM3"
#define GM1_TXT_RSA_SM1_SM3		"RSA-SM1-SM3"
#define GM1_TXT_RSA_SM1_SHA1		"RSA-SM1-SHA1"
#define GM1_TXT_ECDHE_SM4_SM3		"ECDHE-SM4-SM3"
#define GM1_TXT_ECC_SM4_SM3		"ECC-SM4-SM3"
#define GM1_TXT_IBSDH_SM4_SM3		"IBSDH-SM4-SM3"
#define GM1_TXT_IBC_SM4_SM3		"IBC-SM4-SM3"
#define GM1_TXT_RSA_SM4_SM3		"RSA-SM4-SM3"
#define GM1_TXT_RSA_SM4_SHA1		"RSA-SM4-SHA1"

/* from GM/T 0024-2014 Table 1 */
#define GM1_AD_UNSUPPORTED_SITE2SITE	200 /* fatal */
#define GM1_AD_NO_AREA			201
#define GM1_AD_UNSUPPORTED_AREATYPE	202
#define GM1_AD_BAD_IBCPARAM		203 /* fatal */
#define GM1_AD_UNSUPPORTED_IBCPARAM	204 /* fatal */
#define GM1_AD_IDENTITY_NEED		205 /* fatal */

#if 0
/* Bits for algorithm_enc (symmetric encryption */
#define SSL_SM1			0x00004000L
#define SSL_SM4			0x00008000L

/* bits for algorithm_mac */
#define SSL_SM3			0x00000040L
#endif

#define SSL_HANDSHAKE_MAC_SM3	0x200

/* SSL_MAX_DIGEST in ssl_locl.h should be update */

#define GM1_PRF_SM3 (SSL_HANDSHAKE_MAC_SM3 << TLS1_PRF_DGST_SHIFT)


/* Server Certificate
 *
 * The server should always send the `Certificate` message to the client.
 *
 * When using RSA, ECC or ECDHE, the certificate list should be the
 * dual-certificats, server's signature certificate and encryption
 * certificate. The specification did not mention if the certificate-chain
 * can also be sent. For typical VPN applications, the root certificates
 * should be deployed beforehand, so the chain will not be so necessary.
 *
 * In RFC 5246:
 *     This is a sequence (chain) of certificates.  The sender's
 *     certificate MUST come first in the list.  Each following
 *     certificate MUST directly certify the one preceding it.
 *
 * When using IBC or IBSDH, the content of this message shoulld be the
 * server's identity and the IBC public parameters.
 *
 *	opaque ASN.1IBCParam<1..2^24-1>;
 *	struct {
 *		opaque ibc_id<1..2^16-1>;
 *		ASN.1IBCParam ibc_parameter;
 *	} Certificate;
 */


/* opaque ASN.1Cert<1..2^24-1>;

      struct {
          ASN.1Cert certificate_list<0..2^24-1>;
      } Certificate;


	opaque ASN.1IBCParam<1..2^24-1>;

	struct {
		opaque ibc_id<1..2^16-1>;
		ASN.1IBCParam ibc_parameter;
	} Certificate;

*/



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

	struct {
		ECParameters curve_params;
		ECPoint public;
	} ServerECDHEParams;



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



*/

#ifdef __cplusplus
}
#endif
#endif

