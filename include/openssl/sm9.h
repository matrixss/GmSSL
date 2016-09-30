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

#ifdef __cplusplus
extern "C" {
#endif

/* system setup */

typedef struct SM9PublicParameters_st {
	ASN1_OBJECT *curve;
	ASN1_OCTET_STRING *Ppub;
} SM9PublicParameters;
DECLARE_ASN1_FUNCTIONS(SM9PublicParameters)

typedef struct SM9MasterSecret_st {
	BIGNUM *ks;
} SM9MasterSecret;
DECLARE_ASN1_FUNCTIONS(SM9MasterSecret)

int SM9_setup(int curve, SM9PublicParameters **mpk, SM9MasterSecret **msk);

/* private key extract */

typedef struct SM9PrivateKey_st {
	ASN1_OCTET_STRING *ds;
} SM9PrivateKey;
DECLARE_ASN1_FUNCTIONS(SM9PrivateKey)

SM9PrivateKey *SM9_extract_private_key(SM9PublicParameters *mpk,
	SM9MasterSecret *msk, const char *id, size_t idlen);

/* encrypt */

typedef struct SM9EncapKey_st {
	ASN1_OCTET_STRING *K;
	ASN1_OCTET_STRING *C;
} SM9EncapKey;
DECLARE_ASN1_FUNCTIONS(SM9EncapKey)

typedef struct SM9Ciphertext_st {
	ASN1_OCTET_STRING *C1;
	ASN1_OCTET_STRING *C2;
	ASN1_OCTET_STRING *C3;
} SM9Ciphertext;
DECLARE_ASN1_FUNCTIONS(SM9Ciphertext)

SM9Ciphertext *SM9_do_encrypt(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen);
int SM9_do_decrypt(SM9PublicParameters *mpk,
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

/* sign */

typedef struct SM9Signature_st {
	ASN1_OCTET_STRING *h;
	ASN1_OCTET_STRING *S;
} SM9Signature;
DECLARE_ASN1_FUNCTIONS(SM9Signature)

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

/* key exchange */


#define SM9_CID_NONSUPERSINGULAR	0x10
#define SM9_CID_SUPERSINGULAR		0x11
#define SM9_EID_TATE			0x01
#define SM9_EID_WEIL			0x02
#define SM9_EID_ATE			0x03
#define SM9_EID_R_ATE			0x04



BIGNUM *SM9_hash1(const EVP_MD *md, const unsigned char *z, size_t zlen,
	const BIGNUM *range);
BIGNUM *SM9_hash2(const EVP_MD *md, const unsigned char *z, size_t zlen,
	const BIGNUM *range);



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
# define SM9_F_SM9_DO_VERIFY                              104
# define SM9_F_SM9_ENCRYPT                                105
# define SM9_F_SM9_EXTRACT_PRIVATE_KEY                    108
# define SM9_F_SM9_HASH1                                  109
# define SM9_F_SM9_HASH2                                  110
# define SM9_F_SM9_SETUP                                  111
# define SM9_F_SM9_SIGN                                   106
# define SM9_F_SM9_VERIFY                                 107

/* Reason codes. */
# define SM9_R_BUFFER_TOO_SMALL                           101
# define SM9_R_ENCRYPT_FAILURE                            102
# define SM9_R_INVALID_CURVE                              103
# define SM9_R_NOT_IMPLEMENTED                            100
# define SM9_R_UNKNOWN_CURVE                              104

# ifdef  __cplusplus
}
# endif
#endif
