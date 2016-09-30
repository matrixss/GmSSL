/* crypto/pbc/pbc_bb1.c */
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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bb1ibe.h>
#include <openssl/pairing.h>

ASN1_SEQUENCE(BB1PublicParameters) = {
	ASN1_SIMPLE(BB1PublicParameters, version, LONG),
	ASN1_SIMPLE(BB1PublicParameters, curve, ASN1_OBJECT),
	ASN1_SIMPLE(BB1PublicParameters, p, BIGNUM),
	ASN1_SIMPLE(BB1PublicParameters, q, BIGNUM),
	ASN1_SIMPLE(BB1PublicParameters, pointP, FpPoint),
	ASN1_SIMPLE(BB1PublicParameters, pointP1, FpPoint),
	ASN1_SIMPLE(BB1PublicParameters, pointP2, FpPoint),
	ASN1_SIMPLE(BB1PublicParameters, pointP3, FpPoint),
	ASN1_SIMPLE(BB1PublicParameters, v, FpPoint),
	ASN1_SIMPLE(BB1PublicParameters, hashfcn, ASN1_OBJECT)
} ASN1_SEQUENCE_END(BB1PublicParameters)
IMPLEMENT_ASN1_FUNCTIONS(BB1PublicParameters)
IMPLEMENT_ASN1_DUP_FUNCTION(BB1PublicParameters)

ASN1_SEQUENCE(BB1MasterSecret) = {
	ASN1_SIMPLE(BB1MasterSecret, version, LONG),
	ASN1_SIMPLE(BB1MasterSecret, alpha, BIGNUM),
	ASN1_SIMPLE(BB1MasterSecret, beta, BIGNUM),
	ASN1_SIMPLE(BB1MasterSecret, gamma, BIGNUM)
} ASN1_SEQUENCE_END(BB1MasterSecret)
IMPLEMENT_ASN1_FUNCTIONS(BB1MasterSecret)
IMPLEMENT_ASN1_DUP_FUNCTION(BB1MasterSecret)

ASN1_SEQUENCE(BB1PrivateKeyBlock) = {
	ASN1_SIMPLE(BB1PrivateKeyBlock, version, LONG),
	ASN1_SIMPLE(BB1PrivateKeyBlock, pointD0, FpPoint),
	ASN1_SIMPLE(BB1PrivateKeyBlock, pointD1, FpPoint)
} ASN1_SEQUENCE_END(BB1PrivateKeyBlock)
IMPLEMENT_ASN1_FUNCTIONS(BB1PrivateKeyBlock)
IMPLEMENT_ASN1_DUP_FUNCTION(BB1PrivateKeyBlock)

 ASN1_SEQUENCE(BB1CiphertextBlock) = {
	ASN1_SIMPLE(BB1CiphertextBlock, version, LONG),
	ASN1_SIMPLE(BB1CiphertextBlock, pointChi0, FpPoint),
	ASN1_SIMPLE(BB1CiphertextBlock, pointChi1, FpPoint),
	ASN1_SIMPLE(BB1CiphertextBlock, nu, BIGNUM),
	ASN1_SIMPLE(BB1CiphertextBlock, y, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(BB1CiphertextBlock)
IMPLEMENT_ASN1_FUNCTIONS(BB1CiphertextBlock)
IMPLEMENT_ASN1_DUP_FUNCTION(BB1CiphertextBlock)



int BB1IBE_setup(PAIRING *pairing, BB1PublicParameters **pmpk, BB1MasterSecret **pmsk)
{
	int ret = 0;
	BB1PublicParameters *mpk = NULL;
	BB1MasterSecret *msk = NULL;
	EC_POINT *point1 = NULL;
	EC_POINT *point2 = NULL;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group;
	const EVP_MD *md;

	if (!pairing || !pmpk || !pmsk) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	mpk = BB1PublicParameters_new();
	msk = BB1MasterSecret_new();
	group = PAIRING_get0_group(pairing);
	point1 = EC_POINT_new(group);
	point2 = EC_POINT_new(group);
	bn_ctx = BN_CTX_new();

	if (!mpk || !msk || !point1 || !point2 || !bn_ctx) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/*
	 * set mpk->version
	 * set mpk->curve
	 * set mpk->p
	 * set mpk->q
	 * set mpk->pointP
	 * set mpk->hashfcn
	 */

	mpk->version = BB1IBE_VERSION;

	OPENSSL_assert(mpk->curve);
	ASN1_OBJECT_free(mpk->curve);
	if (!(mpk->curve = OBJ_nid2obj(EC_GROUP_get_curve_name(group)))) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, PAIRING_R_NOT_NAMED_CURVE);
		goto end;
	}

	if (!BN_copy(mpk->p, PAIRING_get0_field(pairing))) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, PAIRING_R_PARSE_PAIRING);
		goto end;
	}

	if (!BN_copy(mpk->q, PAIRING_get0_order(pairing))) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, PAIRING_R_PARSE_PAIRING);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, PAIRING_get0_generator(pairing),
		mpk->pointP->x, mpk->pointP->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, PAIRING_R_PARSE_PAIRING);
		goto end;
	}

	if (!(md = PAIRING_nbits_to_md(BN_num_bits(mpk->p) * 2 * 8))) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, PAIRING_R_PARSE_PAIRING);
		goto end;
	}
	ASN1_OBJECT_free(mpk->hashfcn);
	if (!(mpk->hashfcn = OBJ_nid2obj(EVP_MD_type(md)))) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, PAIRING_R_PARSE_PAIRING);
		goto end;
	}

	/* set msk->version
	 * random msk->alpha in [1, q - 1]
	 * random msk->beta  in [1, q - 1]
	 * random msk->gamma in [1, q - 1]
	 */

	msk->version = BB1IBE_VERSION;

	do {
		if (!BN_rand_range(msk->alpha, mpk->q)) {
			PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(msk->alpha));

	do {
		if (!BN_rand_range(msk->beta, mpk->q)) {
			PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(msk->beta));

	do {
		if (!BN_rand_range(msk->gamma, mpk->q)) {
			PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(msk->gamma));

	/*
	 * mpk->pointP1 = msk->alpha * mpk->pointP
	 * mpk->pointP2 = msk->beta  * mpk->pointP
	 */

	if (!EC_POINT_mul(group, point1, msk->alpha, NULL, NULL, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinated_GFp(group, point1,
		mpk->pointP1->x, mpk->pointP1->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_mul(group, point2, msk->beta, NULL, NULL, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinated_GFp(group, point2,
		mpk->pointP2->x, mpk->pointP2->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	/* mpk->v = e(mpk->pointP1, mpk->pointP2) in GF(p^2) */

	if (!PAIRING_compute_tate_GFp(pairing, mpk->v, point1, point2, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_PAIRING_LIB);
		goto end;
	}

	/*
	 * mpk->pointP3 = msk->gamma * mpk->pointP
	 * (careful: re-use tmp variable `point1` for pointP3)
	 */

	if (!EC_POINT_mul(group, point1, msk->gamma, NULL, NULL, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinated_GFp(group, point1,
		mpk->pointP3->x, mpk->pointP3->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	*pmpk = mpk;
	*pmsk = msk;
	ret = 1;

end:
	if (!ret) {
		BB1PublicParameters_free(mpk);
		BB1MasterSecret_free(msk);
		*pmpk = NULL;
		*pmsk = NULL;
	}
	EC_POINT_free(point1);
	EC_POINT_free(point2);
	BN_CTX_free(bn_ctx);
	return ret;
}

BB1PrivateKeyBlock *BB1IBE_extract_private_key(BB1PublicParameters *mpk,
	BB1MasterSecret *msk, const char *id, size_t idlen)
{
	int e = 1;
	BB1PrivateKeyBlock *ret = NULL;
	EC_POINT *point = NULL;
	BIGNUM *r = NULL;
	BIGNUM *y = NULL;
	BIGNUM *hid = NULL;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group;
	const EVP_MD *md;

	if (!mpk || !msk || !id || idlen <= 0) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}

	ret = BB1PrivateKeyBlock_new();
	group = PAIRING_get0_group(pairing);
	point = EC_POINT_new(group);
	r = BN_new();
	y = BN_new();
	hid = BN_new();
	bn_ctx = BN_CTX_new();

	if (!ret || !point || !r || !y || !hid || !bn_ctx) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* md = mpk->hashfcn */
	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, PAIRING_R_INVALID_MD);
		goto end;
	}

	/* set ret->version */
	ret->version = BB1IBE_VERSION;

	/* random r in [1, q - 1] */
	do {
		if (!BN_rand_range(r, mpk->q)) {
			PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY,
				ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(r));

	/* hid = HashToRange(id), hid in [0, q - 1] */
	if (!PAIRING_hash_to_range(md, id, idlen, hid)) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_PAIRING_LIB);
		goto end;
	}

	/* y = msk->alpha * msk->beta + r * (msk->alpha * hid + msk->gamma) in F_q
	 *	hid = hid * msk->alpha
	 *	hid = hid + msk->gamma
	 *	hid = hid * r
	 *	y = msk->alpha * msk->beta
	 *	y = y + hid
	 */
	if (!BN_mod_mul(hid, hid, msk->alpha, mpk->q, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_add(hid, hid, msk->gamma, mpk->q, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(hid, hid, r, mpk->q, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_mul(y, msk->alpha, msk->beta, mpk->q, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_add(y, y, hid, mpk->q, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* sk->pointD0 = y * mpk->pointP */
	if (!EC_POINT_mul(group, point, y, NULL, NULL, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		ret->pointD0->x, ret->pointD0->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* sk->pointD1 = r * mpk->pointP */
	if (!EC_POINT_mul(group, point, r, NULL, NULL, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		ret->pointD1->x, ret->pointD1->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BB1IBE_EXTRACT_PRIVATE_KEY, ERR_R_EC_LIB);
		goto end;
	}

	e = 0;

end:
	if (e && ret) {
		BB1PrivateKeyBlock_free(ret);
		ret = NULL;
	}
	EC_POINT_free(point);
	BN_free(r);
	BN_free(y);
	BN_free(hid);
	BN_CTX_free(bn_ctx);
	return ret;
}

/*
 * return H(H(m)||m) || H(m), return length is 2*hashlen
 */
static int BB1IBE_double_hash(const EVP_MD *md, const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen)
{
	int ret = 0;
	EVP_MD_CTX *ctx = NULL;
	unsigned int len = EVP_MD_size(md);

	if (!md || !in || inlen <= 0 || !out || !(*outlen)) {
		PAIRINGerr(PAIRING_F_BB1IBE_DOUBLE_HASH, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (*outlen < EVP_MD_size(md)) {
		PAIRINGerr(PAIRING_F_BB1IBE_DOUBLE_HASH, PAIRING_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (!EVP_Digest(in, inlen, out + EVP_MD_size(md), &len, md, NULL)) {
		PAIRINGerr(PAIRING_F_BB1IBE_DOUBLE_HASH, ERR_R_EVP_LIB);
		goto end;
	}

	if (!(ctx = EVP_MD_CTX_new())) {
		PAIRINGerr(PAIRING_F_BB1IBE_DOUBLE_HASH, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EVP_DigestInit_ex(ctx, md, NULL)) {
		PAIRINGerr(PAIRING_F_BB1IBE_DOUBLE_HASH, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(ctx, out + EVP_MD_size(md), EVP_MD_size(md))) {
		PAIRINGerr(PAIRING_F_BB1IBE_DOUBLE_HASH, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(ctx, in, inlen)) {
		PAIRINGerr(PAIRING_F_BB1IBE_DOUBLE_HASH, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestFinal_ex(ctx, out, &len)) {
		PAIRINGerr(PAIRING_F_BB1IBE_DOUBLE_HASH, ERR_R_EVP_LIB);
		goto end;
	}

	*outlen = EVP_MD_size(md) * 2;
	ret = 1;
end:
	EVP_MD_CTX_free(ctx);
	return ret;
}


BB1CiphertextBlock *BB1IBE_do_encrypt(BB1PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	const char *id, size_t idlen)
{


	/* random s in [1, q - 1] */


	/* w = (mpk->v)^s in F_p^2 */


	/* ret->pointChi0 = s * mpk->pointP */


	/* hid = HashToRange(id) in F_q */


	/* ret->y = s * hid */


	/* ret->pointChi1 = ret->y * mpk->pointP1 + s * mpk->pointP3 */


	/* (x0, y0) = ret->pointChi0 */
	/* (x1, y1) = ret->pointChi1 */



	/* psi = Canonical(w, order=1, mod=p) */



	/* h1 = double_hash(psi) */


	/* ret->y = HashBytes(h1), |ret->y| == |m| */



	/* ret->y = ret->y xor m */



	/* sigma = y1 || x1 || y0 || x0 || ret->y || psi */


	/* h2 = double_hash(sigma) */


	/* rho = HashToRange(h2), rho in [0, q - 1] */


	/* ret->u = s + rho (mod q) */



	PAIRINGerr(PAIRING_F_BB1IBE_DO_ENCRYPT, ERR_R_PAIRING_LIB);
	return NULL;
}

int BB1IBE_do_decrypt(BB1PublicParameters *mpk,
	const BB1CiphertextBlock *in, unsigned char *out, size_t *outlen,
	BB1PrivateKeyBlock *sk)
{
	PAIRINGerr(PAIRING_F_BB1IBE_DO_DECRYPT, ERR_R_PAIRING_LIB);
	return 0;
}

/* FIXME: accurate result can be calculated from mpk and inlen */
static int BB1PublicParameters_size(BB1PublicParameters *mpk,
	size_t inlen, size_t *outlen)
{
	size_t len = 0;
	len += (OPENSSL_ECC_MAX_FIELD_BITS/8) * 5;
	len += inlen;
	len += EVP_MAX_MD_SIZE;
	len += 256; /* caused by version and DER encoding */
	*outlen = len;
	return 1;
}

int BB1IBE_encrypt(BB1PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen)
{
	int ret = 0;
	BB1CiphertextBlock *c = NULL;
	unsigned char *p;
	size_t len;

	if (!mpk || !in || inlen <= 0 || !outlen || !id || idlen <= 0) {
		PAIRINGerr(PAIRING_F_BB1IBE_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!BB1PublicParameters_size(mpk, inlen, &len)) {
		PAIRINGerr(PAIRING_F_BB1IBE_ENCRYPT, PAIRING_R_COMPUTE_OUTLEN_FAILURE);
		return 0;
	}
	if (!out) {
		*outlen = len;
		return 1;
	}
	if (*outlen < len) {
		PAIRINGerr(PAIRING_F_BB1IBE_ENCRYPT, PAIRING_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (!(c = BB1IBE_do_encrypt(mpk, in, inlen, id, idlen))) {
		PAIRINGerr(PAIRING_F_BB1IBE_ENCRYPT, PAIRING_R_ENCRYPT_FAILURE);
		goto end;
	}

	p = out;
	if (!i2d_BB1CiphertextBlock(c, &p)) {
		PAIRINGerr(PAIRING_F_BB1IBE_ENCRYPT, PAIRING_R_I2D_FAILURE);
		goto end;
	}
	len = p - out;

	*outlen = len;
	ret = 1;

end:
	BB1CiphertextBlock_free(c);
	return ret;
}

int BB1IBE_decrypt(BB1PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	BB1PrivateKeyBlock *sk)
{
	int ret = 0;
	BB1CiphertextBlock *c = NULL;
	const unsigned char *p;

	if (!mpk || !in || inlen <= 0 || !outlen || !sk) {
		PAIRINGerr(PAIRING_F_BB1IBE_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!out) {
		*outlen = inlen;
		return 1;
	}
	if (*outlen < inlen) {
		PAIRINGerr(PAIRING_F_BB1IBE_DECRYPT, PAIRING_R_BUFFER_TOO_SMALL);
		return 0;
	}

	//FIXME: do we need to check no extra input?
	p = in;
	if (!(c = d2i_BB1CiphertextBlock(NULL, &p, inlen))) {
		PAIRINGerr(PAIRING_F_BB1IBE_DECRYPT, PAIRING_R_D2I_FAILURE);
		goto end;
	}

	if (!BB1IBE_do_decrypt(mpk, c, out, outlen, sk)) {
		PAIRINGerr(PAIRING_F_BB1IBE_DECRYPT, PAIRING_R_DECRYPT_FAILURE);
		goto end;
	}

	ret = 1;
end:
	BB1CiphertextBlock_free(c);
	return ret;
}

