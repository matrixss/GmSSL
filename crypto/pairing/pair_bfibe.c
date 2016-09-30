/* crypto/pbc/pbc_bf.c */
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bfibe.h>
#include <openssl/pairing.h>

ASN1_SEQUENCE(BFPublicParameters) = {
	ASN1_SIMPLE(BFPublicParameters, version, LONG),
	ASN1_SIMPLE(BFPublicParameters, curve, ASN1_OBJECT),
	ASN1_SIMPLE(BFPublicParameters, p, BIGNUM),
	ASN1_SIMPLE(BFPublicParameters, q, BIGNUM),
	ASN1_SIMPLE(BFPublicParameters, pointP, FpPoint),
	ASN1_SIMPLE(BFPublicParameters, pointPpub, FpPoint),
	ASN1_SIMPLE(BFPublicParameters, hashfcn, ASN1_OBJECT)
} ASN1_SEQUENCE_END(BFPublicParameters)
IMPLEMENT_ASN1_FUNCTIONS(BFPublicParameters)
IMPLEMENT_ASN1_DUP_FUNCTION(BFPublicParameters)

ASN1_SEQUENCE(BFMasterSecret) = {
	ASN1_SIMPLE(BFMasterSecret, version, LONG),
	ASN1_SIMPLE(BFMasterSecret, masterSecret, BIGNUM)
} ASN1_SEQUENCE_END(BFMasterSecret)
IMPLEMENT_ASN1_FUNCTIONS(BFMasterSecret)
IMPLEMENT_ASN1_DUP_FUNCTION(BFMasterSecret)

ASN1_SEQUENCE(BFPrivateKeyBlock) = {
	ASN1_SIMPLE(BFPrivateKeyBlock, version, LONG),
	ASN1_SIMPLE(BFPrivateKeyBlock, privateKey, FpPoint)
} ASN1_SEQUENCE_END(BFPrivateKeyBlock)
IMPLEMENT_ASN1_FUNCTIONS(BFPrivateKeyBlock)
IMPLEMENT_ASN1_DUP_FUNCTION(BFPrivateKeyBlock)

ASN1_SEQUENCE(BFCiphertextBlock) = {
	ASN1_SIMPLE(BFCiphertextBlock, version, LONG),
	ASN1_SIMPLE(BFCiphertextBlock, u, FpPoint),
	ASN1_SIMPLE(BFCiphertextBlock, v, ASN1_OCTET_STRING),
	ASN1_SIMPLE(BFCiphertextBlock, w, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(BFCiphertextBlock)
IMPLEMENT_ASN1_FUNCTIONS(BFCiphertextBlock)
IMPLEMENT_ASN1_DUP_FUNCTION(BFCiphertextBlock)


int BFIBE_setup(PAIRING *pairing, BFPublicParameters **pmpk, BFMasterSecret **pmsk)
{
	int ret = 0;
	BFPublicParameters *pk = NULL;
	BFMasterSecret *sk = NULL;
	EC_POINT *point = NULL;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group;
	const EVP_MD *md;

	if (!pairing || !pmpk || !pmsk) {
		PAIRINGerr(PAIRING_F_BFIBE_SETUP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	mpk = BFPublicParameters_new();
	msk = BFMasterSecret_new();
	group = PAIRING_get0_group(pairing);
	point = EC_POINT_new(group);
	bn_ctx = BN_CTX_new();

	if (!mpk || !msk || !point || !bn_ctx) {
		PAIRINGerr(PAIRING_F_BFIBE_SETUP, ERR_R_MALLOC_FAILURE);
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

	mpk->version = BFIBE_VERSION;

	OPENSSL_assert(mpk->curve);
	ASN1_OBJECT_free(mpk->curve);
	if (!(mpk->curve = OBJ_nid2obj(EC_GROUP_get_curve_name(group)))) {
		PAIRINGerr(PAIRING_F_BFIBE_SETUP, PAIRING_R_NOT_NAMED_CURVE);
		goto end;
	}

	if (!BN_copy(mpk->p, PAIRING_get0_field(pairing))) {
		PAIRINGerr(PAIRING_F_BFIBE_SETUP, PAIRING_R_PARSE_PAIRING);
		goto end;
	}

	if (!BN_copy(mpk->q, PAIRING_get0_order(pairing))) {
		PAIRINGerr(PAIRING_F_BFIBE_SETUP, PAIRING_R_PARSE_PAIRING);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, PAIRING_get0_generator(pairing),
		mpk->pointP->x, mpk->pointP->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_SETUP, PAIRING_R_PARSE_PAIRING);
		goto end;
	}

	if (!(md = PAIRING_nbits_to_md(BN_num_bits(mpk->p) * 2 * 8))) {
		PAIRINGerr(PAIRING_F_BFIBE_SETUP, PAIRING_R_PARSE_PAIRING);
		goto end;
	}
	ASN1_OBJECT_free(mpk->hashfcn);
	if (!(mpk->hashfcn = OBJ_nid2obj(EVP_MD_type(md)))) {
		PAIRINGerr(PAIRING_F_BFIBE_SETUP, PAIRING_R_PARSE_PAIRING);
		goto end;
	}

	/* set msk->version
	 * random msk->masterSecret in [2, q - 1]
	 */

	msk->version = BFIBE_VERSION;

	do {
		if (!BN_rand_range(sk->privateKey, pk->q)) {
			PAIRINGerr(PAIRING_F_BFIBE_SETUP, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(sk->privateKey) || BN_is_one(sk->privateKey));

	/* mpk->pointPpub = msk->masterSecret * mpk->pointP */

	if (!EC_POINT_mul(group, point, sk->privateKey, NULL, NULL, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		mpk->pointPpub->x, mpk->pointPpub->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_SETUP, ERR_R_EC_LIB);
		goto end;
	}

	*pmpk = mpk;
	*pmsk = msk;
	ret = 1;

end:
	if (!ret) {
		BFPublicParameters_free(mpk);
		BFMasterSecret_free(msk);
		*pmpk = NULL;
		*pmsk = NULL;
	}
	EC_POINT_free(point);
	BN_CTX_free(bn_ctx);
	PAIRINGerr(PAIRING_F_BFIBE_SETUP, ERR_R_PAIRING_LIB);
	return 0;
}

BFPrivateKeyBlock *BFIBE_extract_private_key(BFPublicParameters *mpk,
	BFMasterSecret *msk, const char *id, size_t idlen)
{
	int e = 1;
	BFPrivateKeyBlock *ret = NULL;
	PAIRING *pairing = NULL;
	EC_POINT *point = NULL;
	EC_POINT *PPub = NULL;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group;
	const EVP_MD *md;

	if (!mpk || !msk || !id || idlen <= 0) {
		PAIRINGerr(PAIRING_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_PASSED_NULL_PARAMTERS);
		return NULL;
	}

	if (!(ret = BFPrivateKeyBlock_new())) {
		PAIRINGerr(PAIRING_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	ret->version = BFIBE_VERSION;

	if (!(pairing = PAIRING_new_type1(mpk->p, mpk->q, mpk->pointP))) {
		PAIRINGerr(PAIRING_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_PAIRING_LIB);
		goto end;
	}

	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		PAIRINGerr(PAIRING_F_BFIBE_EXTRACT_PRIVATE_KEY,
			PAIRING_R_INVALID_BFIBE_HASHFUNC);
		goto end;
	}

	group = PAIRING_get0_group(pairing);
	point = EC_POINT_new(group);
	bn_ctx = BN_CTX_new();
	if (!point || !bn_ctx) {
		PAIRINGerr(PAIRING_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!PAIRING_hash_to_point(pairing, md, id, idlen, point, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_PAIRING_LIB);
		goto end;
	}

	if (!EC_POINT_mul(group, point, msk->masterSecret, NULL, NULL, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_PAIRING_LIB);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, point,
		ret->privateKey->x, ret->privateKey->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_EXTRACT_PRIVATE_KEY, ERR_R_PAIRING_LIB);
		goto end;
	}

	e = 0;
end:
	if (e && ret) {
		BFPrivateKeyBlock_free(ret);
		ret = NULL;
	}
	PAIRING_free(pairing);
	EC_POINT_free(point);
	BN_CTX_free(bn_ctx);
	return ret;
}

/*
 * r = rand(), |r| = hashlen
 * k = HashToRange(r||Hash(m), q), k in [0, q-1]
 * U = [k]P in E/F_p
 * Q = HashToPoint(ID) in E/F_p
 * v = Hash(e(Ppub, Q)^k) xor r, |v| == hashlen
 * w = HashBytes(r) xor m
 */
BFCiphertextBlock *BFIBE_do_encrypt(BFPublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	const char *id, size_t idlen)
{
	int e = 1;
	BFCiphertextBlock *ret = NULL;
	PAIRING *pairing = NULL;
	EC_POINT *point = NULL;
	EC_POINT *Ppub = NULL;
	BIGNUM *k = NULL;
	BN_GFP2 *theta = NULL;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group;
	const EVP_MD *md;
	unsigned char rho[EVP_MAX_MD_SIZE * 2];
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned int len;

	if (!mpk || !in || inlen <= 0 || !id || idlen <= 0) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_PASSED_NULL_PARAMETERS);
		return NULL;
	}

	/* prepare values */

	if (!(pairing = PAIRING_new_type1(mpk->p, mpk->q, mpk->pointP))) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_PAIRING_LIB);
		goto end;
	}

	group = PAIRING_get0_group(pairing);
	point = EC_POINT_new(group);
	Ppub = EC_POINT_new(group);
	k = BN_new();
	theta = BN_GFP2_new();
	bn_ctx = BN_CTX_new();
	if (!point || !Ppub || !k || !theta || !bn_ctx) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(group, Ppub,
		mpk->pointPpub->x, mpk->pointPpub->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, PAIRING_R_INVALID_BFIBE_HASHFUNC);
		goto end;
	}

	if (!(ret = BFCiphertextBlock_new())) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	/* start */
	ret->version = BFIBE_VERSION;

	/* r = Rand(), |r| = hashlen */
	if (!RAND_bytes(rho, EVP_MD_size(md))) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, PAIRING_R_RAND_FAILURE);
		goto end;
	}

	/* k = HashToRange(r||Hash(in), q) in [0, q - 1] */
	len = sizeof(rho) - EVP_MD_size(md);
	if (!EVP_Digest(in, inlen, rho + EVP_MD_size(md), &len, md, NULL)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	if (!PAIRING_hash_to_range(md, rho, EVP_MD_size(md)*2, k, mpk->q)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_PAIRING_LIB);
		goto end;
	}

	/* U = [k]P in E/F_p */
	if (!EC_POINT_mul(group, point, k, NULL, NULL, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, point, ret->u->x, ret->u->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* Q = HashToPoint(ID) in E/F_p */
	if (!PAIRING_hash_to_point(pairing, md, id, idlen, point, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_PAIRING_LIB);
		goto end;
	}

	/* theta = e(P_pub, Q_id)^k */
	if (!PAIRING_compute_tate_GFp2(pairing, theta, Ppub, point, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_PAIRING_LIB);
		goto end;
	}
	if (!BN_GFP2_exp(theta, theta, k, mpk->p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_PAIRING_LIB);
		goto end;
	}

	/* v = Hash(theta) xor rho */
	if (!BN_GFP2_canonical(theta, buf, &len, 0, mpk->p)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_PAIRING_LIB);
		goto end;
	}
	if (!EVP_Digest(buf, len, buf, &len, md, NULL)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	for (i = 0; i < EVP_MD_size(md); i++) {
		buf[i] ^= rho[i];
	}
	if (!ASN1_OCTET_STRING_set(ret->v, buf, len)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_PAIRING_LIB);
		goto end;
	}

	/*  w = HashBytes(r) xor m */
	if (!ASN1_OCTET_STRING_set(ret->w, NULL, inlen)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!PAIRING_hash_bytes(md, rho, EVP_MD_size(md), inlen, ret->w->data)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_ENCRYPT, ERR_R_PAIRING_LIB);
		goto end;
	}
	for (i = 0; i < inlen; i++) {
		ret->w->data[i] ^= in[i];
	}

	e = 0;
end:
	if (e && ret) {
		BFCiphertextBlock_free(ret);
		ret = NULL;
	}
	PAIRING_free(pairing);
	EC_POINT_free(point);
	EC_POINT_free(Ppub);
	BN_free(k);
	BN_GFP2_free(theta);
	BN_CTX_free(bn_ctx);
	return ret;
}

int BFIBE_do_decrypt(BFPublicParameters *mpk,
	const BFCiphertextBlock *in, unsigned char *out, size_t *outlen,
	BFPrivateKeyBlock *sk)
{
	int ret = 0;
	PAIRING *pairing = NULL;
	EC_POINT *secret_point = NULL;
	EC_POINT *point = NULL;
	EC_POINT *Ppub = NULL;
	BIGNUM *k = NULL;
	BN_GFP2 *theta = NULL;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *group;
	const EVP_MD *md;
	unsigned char rho[EVP_MAX_MD_SIZE * 2];
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned int len;

	/* prepare values */

	if (!(pairing = PAIRING_new_type1(mpk->p, mpk->q, mpk->pointP))) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_DECRYPT, ERR_R_PAIRING_LIB);
		goto end;
	}

	group = PAIRING_get0_group(pairing);
	secret_point = EC_POINT_new(group);
	point = EC_POINT_new(group);
	Ppub = EC_POINT_new(group);
	k = BN_new();
	theta = BN_GFP2_new();
	bn_ctx = BN_CTX_new();
	if (!secret_point || !point || !Ppub || !k || !theta || !bn_ctx) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(group, Ppub,
		mpk->pointPpub->x, mpk->pointPpub->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}

	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_DECRYPT, PAIRING_R_INVALID_BFIBE_HASHFUNC);
		goto end;
	}

	/* get ciphertext U */
	if (!EC_POINT_set_affine_coordinates_GFp(group, point,
		in->u->x, in->u->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* get private key S_id in E/F_p */
	if (!EC_POINT_set_affine_coordinates_GFp(group, secret_point,
		sk->privateKey->x, sk->privateKey->y, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* theta = e(U, S_id) */
	if (!PAIRING_compute_tate_GFp2(pairing, theta, point, secret_point, bn_ctx)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_DECRYPT, ERR_R_PAIRING_LIB);
		goto end;
	}

	/* rho = Hash(theta) xor V */
	if (!BN_GFP2_canonical(theta, buf, &len, 0, mpk->p)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_DECRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EVP_Digest(buf, len, buf, &len, md, NULL)) {
		PAIRINGerr(PAIRING_F_BFIBE_DO_DECRYPT, ERR_R_EVP_LIB);
		goto end;
	}
	for (i = 0; i < EVP_MD_size(md); i++) {
		rho[i] = buf[i] ^ in->v->data[i];
	}

	/* m = HashBytes(|W|, rho, hashfcn) xor W */
	if (!PAIRING_hash_bytes(md, rho, EVP_MD_size(md), in->w->length, out)) {
		goto end;
	}
	for (i = 0; i < in->w->length; i++) {
		out[i] ^= in->w->data[i];
	}

	/* t = hashfcn(m) */
	if (!EVP_Digest(out, in->w->length, rho + EVP_MD_size(md), &len, md, NULL)) {
		goto end;
	}

	/* l = HashToRange(rho || t, q, hashfcn */

	if (!PAIRING_hash_to_range()) {
	}

	/* Verify that U = [l]P: */

	if (!EC_POINT_mul(group, point, k, NULL, NULL, bn_ctx)) {
		goto end;
	}

	if (!EC_POINT_is_equal_FpPoint(group, point, in->U, bn_ctx)) {
		goto end;
	}

	ret = 1;

end:
	PAIRING_free(pairing);
	EC_POINT_free(point);
	BN_free(k);
	BN_GFP2_free(theta);
	BN_CTX_free(bn_ctx);
	return 0;
}

/* FIXME: accurate result can be calculated from mpk and inlen */
static int BFPublicParameters_size(BFPublicParameters *mpk,
	size_t inlen, size_t *outlen)
{
	size_t len = 0;
	len += (OPENSSL_ECC_MAX_FIELD_BITS/8) * 2;
	len += inlen;
	len += EVP_MAX_MD_SIZE;
	len += 128; /* caused by version and DER encoding */
	*outlen = len;
	return 1;
}

int BFIBE_encrypt(BFPublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen)
{
	int ret = 0;
	BFCiphertextBlock *c = NULL;
	unsigned char *p;
	size_t len;

	if (!mpk || !in || inlen <= 0 || !outlen || !id || idlen <= 0) {
		PAIRINGerr(PAIRING_F_BFIBE_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!BFPublicParameters_size(mpk, inlen, &len)) {
		PAIRINGerr(PAIRING_F_BFIBE_ENCRYPT, PAIRING_R_COMPUTE_OUTLEN_FAILURE);
		return 0;
	}
	if (!out) {
		*outlen = len;
		return 1;
	}
	if (*outlen < len) {
		PAIRINGerr(PAIRING_F_BFIBE_ENCRYPT, PAIRING_R_BUFFER_TOO_SMALL;
		return 0;
	}

	if (!(c = BFIBE_do_encrypt(mpk, in, inlen, id, idlen))) {
		PAIRINGerr(PAIRING_F_BFIBE_ENCRYPT, PAIRING_R_ENCRYPT_FAILURE);
		goto end;
	}

	p = out;
	if (!i2d_BFCiphertextBlock(c, &p)) {
		PAIRINGerr(PAIRING_F_BFIBE_ENCRYPT, PAIRING_R_I2D_FAILURE);
		goto end;
	}
	len = p - out;

	*outlen = len;
	ret = 1;

end:
	BFCiphertextBlock_free(c);
	return ret;
}

int BFIBE_decrypt(BFPublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	BFPrivateKeyBlock *sk)
{
	int ret = 0;
	BFCiphertextBlock *c = NULL;
	const unsigned char *p;

	if (!mpk || !in || inlen <= 0 || !outlen || !sk) {
		PAIRINGerr(PAIRING_F_BFIBE_DECRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!out) {
		*outlen = inlen;
		return 1;
	}
	if (*outlen < inlen) {
		PAIRINGerr(PAIRING_F_BFIBE_DECRYPT, PAIRING_R_BUFFER_TOO_SMALL);
		return 0;
	}

	//FIXME: do we need to check no extra input?
	p = in;
	if (!(c = d2i_BFCiphertextBlock(NULL, &p, inlen))) {
		PAIRINGerr(PAIRING_F_BFIBE_DECRYPT, PAIRING_R_D2I_FAILURE);
		goto end;
	}

	if (!BFIBE_do_decrypt(mpk, c, out, outlen, sk)) {
		PAIRINGerr(PAIRING_F_BFIBE_DECRYPT, PAIRING_R_DECRYPT_FAILURE);
		goto end;
	}

	ret = 1;
end:
	BFCiphertextBlock_free(c);
	return ret;
}


