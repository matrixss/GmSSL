/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
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

#ifndef HEADER_SM9_H
#define HEADER_SM9_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/pairing.h>

/* Curve ID */
#define SM9_CID_TYPE0CURVE	0x10
#define SM9_CID_TYPE1CURVE	0x11
#define SM9_CID_TYPE2CURVE	0x12

/* Pairing ID */
#define SM9_EID_TATE		0x01
#define SM9_EID_WEIL		0x02
#define SM9_EID_ATE		0x03
#define SM9_EID_RATE		0x04

#define SM9_MAX_ID_LENGTH	127

/* not clear what it is */
#define SM9_HID			0xc9

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SM9PublicParameters_st {
	ASN1_OBJECT *curve;
	BIGNUM *p;
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *beta;
	BIGNUM *order;
	BIGNUM *cofactor;
	BIGNUM *k;
	ASN1_OCTET_STRING *pointP1;
	ASN1_OCTET_STRING *pointP2;
	ASN1_OBJECT *pairing;
	ASN1_OCTET_STRING *pointPpub;
	BIGNUM *g1; /* g1 = e(P1, Ppub) */
	BIGNUM *g2; /* g2 = e(Ppub, P2) */
	ASN1_OBJECT *hashfcn;
} SM9PublicParameters;
DECLARE_ASN1_FUNCTIONS(SM9PublicParameters)

typedef struct SM9MasterSecret_st {
	BIGNUM *masterSecret;
} SM9MasterSecret;
DECLARE_ASN1_FUNCTIONS(SM9MasterSecret)

typedef struct SM9PrivateKey_st {
	ASN1_OCTET_STRING *privatePoint;
} SM9PrivateKey;
DECLARE_ASN1_FUNCTIONS(SM9PrivateKey)

typedef struct SM9Ciphertext_st {
	ASN1_OCTET_STRING *pointC1;
	ASN1_OCTET_STRING *c2;
	ASN1_OCTET_STRING *c3;
} SM9Ciphertext;
DECLARE_ASN1_FUNCTIONS(SM9Ciphertext)

typedef struct SM9Signature_st {
	BIGNUM *h;
	ASN1_OCTET_STRING *pointS;
} SM9Signature;
DECLARE_ASN1_FUNCTIONS(SM9Signature)

typedef struct {
	const EVP_MD *kdf_md;
	const EVP_CIPHER *enc_cipher;
	const EVP_CIPHER *cmac_cipher;
	const EVP_MD *hmac_md;
} SM9EncParameters;

int SM9_setup_type1curve(const EC_GROUP *group, const EVP_MD *md,
	SM9PublicParameters **mpk, SM9MasterSecret **msk);
SM9PrivateKey *SM9_extract_private_key(SM9PublicParameters *mpk,
	SM9MasterSecret *msk, const char *id, size_t idlen);


int SM9_wrap_key(SM9PublicParameters *mpk, KDF_FUNC kdf_func,
	unsigned char *key, size_t keylen,
	unsigned char *wrapped, size_t *wrappedlen,
	const char *id, size_t idlen);
int SM9_unwrap_key(SM9PublicParameters *mpk, KDF_FUNC kdf_func,
	unsigned char *key, size_t keylen,
	const unsigned char *wrapped, size_t wrappedlen,
	SM9PrivateKey *sk);

SM9Ciphertext *SM9_do_encrypt(SM9PublicParameters *mpk,
	SM9EncParameters *param, const unsigned char *in, size_t inlen,
	const char *id, size_t idlen);
int SM9_do_decrypt(SM9PublicParameters *mpk, SM9EncParameters *param,
	const SM9Ciphertext *in, unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk);

int SM9_encrypt(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen);
int SM9_decrypt(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk);

SM9Signature *SM9_do_sign(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	SM9PrivateKey *sk);
int SM9_do_verify(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	const SM9Signature *sig, const char *id, size_t idlen);
int SM9_sign(SM9PublicParameters *mpk, const unsigned char *dgst,
	size_t dgstlen, unsigned char *sig, size_t *siglen,
	SM9PrivateKey *sk);
int SM9_verify(SM9PublicParameters *mpk, const unsigned char *dgst,
	size_t dgstlen, const unsigned char *sig, size_t siglen,
	const char *id, size_t idlen);

int SM9_hash1(const EVP_MD *md, BIGNUM **r, const char *id, size_t idlen,
	unsigned char hid, const BIGNUM *range, BN_CTX *ctx);

int SM9_hash2(const EVP_MD *md, BIGNUM **r,
	const unsigned char *data, size_t datalen,
	const unsigned char *elem, size_t elemlen,
	const BIGNUM *range, BN_CTX *ctx);


/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_SM9_strings(void);

/* Error codes for the SM9 functions. */

/* Function codes. */
# define SM9_F_SM9_DECRYPT                                100
# define SM9_F_SM9_DO_DECRYPT                             101
# define SM9_F_SM9_DO_ENCRYPT                             102
# define SM9_F_SM9_DO_SIGN                                103
# define SM9_F_SM9_DO_SIGN_TYPE1CURVE                     113
# define SM9_F_SM9_DO_VERIFY                              104
# define SM9_F_SM9_ENCRYPT                                105
# define SM9_F_SM9_EXTRACT_PRIVATE_KEY                    108
# define SM9_F_SM9_HASH1                                  109
# define SM9_F_SM9_HASH2                                  110
# define SM9_F_SM9_SETUP                                  111
# define SM9_F_SM9_SETUP_TYPE1CURVE                       112
# define SM9_F_SM9_SIGN                                   106
# define SM9_F_SM9_VERIFY                                 107

/* Reason codes. */
# define SM9_R_BUFFER_TOO_SMALL                           101
# define SM9_R_ENCRYPT_FAILURE                            102
# define SM9_R_INVALID_CURVE                              103
# define SM9_R_INVALID_DIGEST                             111
# define SM9_R_INVALID_ID                                 108
# define SM9_R_INVALID_MD                                 109
# define SM9_R_INVALID_TYPE1CURVE                         105
# define SM9_R_NOT_IMPLEMENTED                            100
# define SM9_R_NOT_NAMED_CURVE                            106
# define SM9_R_PARSE_PAIRING                              107
# define SM9_R_UNKNOWN_CURVE                              104
# define SM9_R_ZERO_ID                                    110

# ifdef  __cplusplus
}
# endif
#endif
