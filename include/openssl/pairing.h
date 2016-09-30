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

#ifndef HEADER_PAIRING_H
#define HEADER_PAIRING_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* solinas prime */
typedef struct {
	int a;
	int b;
	int s;
	int c;
} BN_SOLINAS;

/* TODO: here give some recommended solinas primes */

int BN_bn2solinas(const BIGNUM *bn, BN_SOLINAS *solinas);
int BN_solinas2bn(const BN_SOLINAS *solinas, BIGNUM *bn);


/* element a in GF(p^2), where a = a0 + a1 * i, i^2 == -1 */
typedef struct {
	BIGNUM *a0;
	BIGNUM *a1;
} BN_GFP2;

BN_GFP2 *BN_GFP2_new(void);
int BN_GFP2_copy(BN_GFP2 *r, const BN_GFP2 *a);
int BN_GFP2_zero(BN_GFP2 *a);
int BN_GFP2_is_zero(const BN_GFP2 *a);
int BN_GFP2_equ(const BN_GFP2 *a, const BN_GFP2 *b);
int BN_GF2P_add(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_sub(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_mul(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_sqr(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_inv(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_div(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_set_bn(BN_GFP2 *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GF2P_add_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p,BN_CTX *ctx);
int BN_GFP2_sub_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_mul_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_div_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
void BN_GFP2_free(BN_GFP2 *a);

int BN_bn2gfp2(const BIGNUM *bn, BN_GFP2 *gfp2, const BIGNUM *p);
int BN_gfp22bn(const BN_GFP2 *gfp2, BIGNUM *bn, const BIGNUM *p);

typedef struct {
	BN_GFP2 *x;
	BN_GFP2 *y;
} EC_POINT_GFP2;

EC_POINT_GFP2 *EC_POINT_GFP2_new(void);
void EC_POINT_GFP2_free(EC_POINT_GFP2 *a);

typedef struct {
	int type;
	EC_GROUP *group;
	/* online */
	BIGNUM *order;
	BIGNUM *eta;
	BIGNUM *zeta;
} PAIRING;

PAIRING *PAIRING_new_by_name(int nid);
void PAIRING_free(PAIRING *a);

const EC_GROUP *PAIRING_get0_group(PAIRING *pairing);
const BIGNUM *PAIRING_get0_order(PAIRING *pairing);
const BIGNUM *PAIRING_get0_field(PAIRING *pairing);


int PAIRING_compute_tate_GFp2(PAIRING *pairing, BN_GFP2 *r,
	const EC_POINT *P, const EC_POINT *Q, BN_CTX *ctx);

/* for ibcs#1 */
typedef struct {
	BIGNUM *x;
	BIGNUM *y;
} FpPoint;
DECLARE_ASN1_FUNCTIONS(FpPoint)

const EVP_MD *PAIRING_nbits_to_md(int nbits);
int PAIRING_hash_to_range(const EVP_MD *md, const char *s, size_t slen,
	BIGNUM *bn, const BIGNUM *range);
int PAIRING_hash_bytes(const EVP_MD *md, const char *s, size_t slen,
	unsigned char *out, size_t len);
int PAIRING_hash_to_point_GFp(PAIRING *pairing, const EVP_MD *md,
	const char *id, size_t idlen, EC_POINT *point, BN_CTX *ctx);
int PAIRING_hash_to_point_GFp2(PAIRING *pairing, const EVP_MD *md,
	const char *id, size_t idlen, EC_POINT_GFP2 *point, BN_CTX *ctx);


/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_PAIRING_strings(void);

/* Error codes for the PAIRING functions. */

/* Function codes. */
# define PAIRING_F_BB1IBE_DECRYPT                         100
# define PAIRING_F_BB1IBE_DOUBLE_HASH                     101
# define PAIRING_F_BB1IBE_DO_DECRYPT                      102
# define PAIRING_F_BB1IBE_DO_ENCRYPT                      103
# define PAIRING_F_BB1IBE_ENCRYPT                         104
# define PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY             105
# define PAIRING_F_BB1IBE_SETUP                           106
# define PAIRING_F_BFIBE_DECRYPT                          107
# define PAIRING_F_BFIBE_DO_DECRYPT                       108
# define PAIRING_F_BFIBE_DO_ENCRYPT                       109
# define PAIRING_F_BFIBE_ENCRYPT                          110
# define PAIRING_F_BFIBE_EXTRACT_PRIVATE_KEY              111
# define PAIRING_F_BFIBE_SETUP                            112
# define PAIRING_F_BN_GFP2_ADD_BN                         113
# define PAIRING_F_BN_GFP2_DIV_BN                         114
# define PAIRING_F_BN_GFP2_MUL_BN                         115
# define PAIRING_F_BN_GFP2_SET_BN                         116
# define PAIRING_F_BN_GFP2_SUB_BN                         117
# define PAIRING_F_PAIRING_EVAL_LINE_GFP2                 118
# define PAIRING_F_PAIRING_EVAL_MILLER_GFP2               119
# define PAIRING_F_PAIRING_PHI_GFP2                       120

/* Reason codes. */
# define PAIRING_R_BN_GFP2_FAILURE                        100
# define PAIRING_R_BUFFER_TOO_SMALL                       101
# define PAIRING_R_COMPUTE_OUTLEN_FAILURE                 110
# define PAIRING_R_D2I_FAILURE                            111
# define PAIRING_R_DECRYPT_FAILURE                        112
# define PAIRING_R_ENCRYPT_FAILURE                        113
# define PAIRING_R_I2D_FAILURE                            114
# define PAIRING_R_INVALID_BFIBE_HASHFUNC                 102
# define PAIRING_R_INVALID_MD                             107
# define PAIRING_R_MILLER_FAILURE                         103
# define PAIRING_R_NOT_IMPLEMENTED                        104
# define PAIRING_R_NOT_NAMED_CURVE                        108
# define PAIRING_R_PARSE_PAIRING                          109
# define PAIRING_R_PHI_FAILURE                            105
# define PAIRING_R_RAND_FAILURE                           106

# ifdef  __cplusplus
}
# endif
#endif
