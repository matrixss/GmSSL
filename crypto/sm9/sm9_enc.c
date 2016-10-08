/* crypto/sm9/sm9_enc.c */
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
#include <openssl/sm9.h>

int SM9_wrap_key(SM9PublicParameters *mpk, size_t outkeylen,
	unsigned char *outkey, unsigned char *outcipher, size_t *outcipherlen,
	const char *id, size_t idlen)
{
	int ret = 0;
	BN_CTX *bn_ctx = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	EC_POINT *Ppub = NULL;
	BN_GFP2 *w = NULL;
	unsigned char *buf = NULL;
	BIGNUM *h;
	BIGNUM *r;
	unsigned char *pbuf;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	size_t size;
	size_t buflen;

	if (!mpk || !key || keylen <= 0 || !clen || !id || idlen <= 0) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* EC_GROUP */
	if (!(group = EC_GROUP_new_type1curve_ex(mpk->p,
		mpk->a, mpk->b, mpk->pointP1->data, mpk->pointP1->length,
		mpk->order, mpk->cofactor, bn_ctx))) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	point = EC_POINT_new(group);
	Ppub = EC_POINT_new(group);
	w = BN_GFP2_new();
	h = BN_CTX_get(bn_ctx);
	r = BN_CTX_get(bn_ctx);

	if (!point || !Ppub || !w || !h || !r) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* h = H1(ID||hid) in range [0, mpk->order] */
	if (!SM9_hash1(md, &h, id, idlen, SM9_HID, mpk->order, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_HASH_FAILURE);
		goto end;
	}

	/* point = mpk->pointP1 * h */
	if (!EC_POINT_mul(group, point, h, NULL, NULL, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* Ppub = mpk->pointPpub */
	if (!EC_POINT_oct2point(group, Ppub,
		mpk->pointPpub->data, mpk->pointPpub->length, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* point = point + Ppub = P1 * H1(ID||hid) + Ppub*/
	if (!EC_POINT_add(group, point, point, Ppub, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* rand r in (0, mpk->order) */
	do {
		if (!BN_rand_range(r, mpk->order)) {
			SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(r));

	/* point = point * r */
	if (!EC_POINT_mul(group, point, NULL, point, r, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* output wrapped = point */
	size = 0; //FIXME
	if (!(size = EC_POINT_point2oct(group, point, point_form,
		wrapped, size, bn_ctx))) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}
	*wrappedlen = size;

	/* get w = mpk->g2 = e(Ppub, P2) in F_p^2 */
	if (!BN_bn2gfp2(mpk->g2, w, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* w = w^r in F_p^2 */
	if (!BN_GFP2_exp(w, w, r, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_BN_LIB);
		goto end;
	}

	/* |buf| = wrappedlen + |w| + idlen */
	buflen = *wrappelen + wlen + idlen;

	/* malloc buf */
	if (!(buf = OPENSSL_malloc(buflen))) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* copy wrapped to buf */
	memcpy(buf, wrapped, *wrappedlen);

	/* canonical w to buf */
	if (!BN_GFP2_canonical(w, pbuf, &size, 0, bn_ctx)) {
		SM9err(SM9_F_SM9_WRAP_KEY, ERR_R_BN_LIB);
		goto end;
	}
	pbuf += size;

	/* copy id to buf */
	memcpy(pbuf, id, idlen);


	/* output key = KDF(C||w||ID), |key| = keylen */
	keylen = 0;
	if (!kdf_func(buf, buflen, key, &keylen)) {
		SM9err(SM9_F_SM9_WRAP_KEY, SM9_R_KDF_FAILURE);
		goto end;
	}

	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	EC_POINT_free(Ppub);
	BN_GFP2_free(w);
	OPENSSL_free(buf);
	return ret;
}

int SM9_unwrap_key(SM9PublicParameters *mpk, size_t keylen,
	const unsigned char *incipher, size_t incipherlen,
	unsigned char *outkey, SM9PrivateKey *sk)
{
	int ret = 0;
	BN_CTX *bn_ctx = NULL;
	EC_GORUP *group = NULL;
	EC_POINT *point = NULL;
	EC_POINT *point1 = NULL;
	BN_GFP2 *w = NULL;
	unsigned char *buf = NULL;
	unsigned char *pbuf;
	size_t buflen, wlen;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	KDF_FUNC key_func;
	int i;

	if (!mpk || !incipher || incipherlen <= 0 || !outkey || outkeylen <= 0 || !sk) {
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* EC_GROUP */
	if (!(group = EC_GROUP_new_type1curve_ex(mpk->p,
		mpk->a, mpk->b, mpk->pointP1->data, mpk->pointP1->length,
		mpk->order, mpk->cofactor, bn_ctx))) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* malloc */
	point = EC_POINT_new(group);
	point1 = EC_POINT_new(group);
	w = BN_GFP2_new();

	if (!point || !point1 || !w) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* point decoded from incipher in curve */
	if (!EC_POINT_oct2point(group, point, incipher, incipherlen, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* point1 decoded from sk->privatePoint */
	if (!EC_POINT_oct2point(group, point1,
		sk->privatePoint->data, sk->privatePoint->length, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* w = e(point, sk->privatePoint) in F_p^2 */
	if (!PAIRING_type1curve_tate(group, w, point, point1, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* wbuflen is canonical w length */
	if (!BN_GFP2_canonical(w, NULL, &wlen, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* buflen = incipherlen + wlen + idlen */
	buflen = incipherlen + wlen + idlen;

	/* buf = malloc(buflen) */
	if (!(buf = OPENSSL_malloc(buflen))) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}
	pbuf = buf;

	/* copy incipher to buf */
	memcpy(pbuf, incipher, incipherlen);
	pbuf += incipherlen;

	/* canonical w to buf */
	if (!BN_GFP2_canonical(w, pbuf, &wlen, mpk->p, bn_ctx)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}
	pbuf += wlen;

	/* copy id to buf */
	memcpy(pbuf, id, idlen);

	/* outkey = KDF(buf, outkeylen) */
	outlen = outkeylen;
	if (!kdf_func(buf, buflen, outkey, &oulen)) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	/* is outkey is all zero, return failed */
	for (i = 0; (i < outkeylen) && (out[i] == 0); i++) {
	}
	if (i == outkeylen) {
		SM9err(SM9_F_SM9_UNWRAP_KEY, ERR_R_EC_LIB);
		goto end;
	}

	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	EC_POINT_free(point1);
	BN_GFP2_free(w);
	OPENSSL_free(buf);
	return ret;
}

SM9Ciphertext *SM9_do_encrypt(SM9PublicParameters *mpk,
	const SM9EncParameters *params,
	const unsigned char *in, size_t inlen,
	const char *id, size_t idlen)
{
	int e = 1;
	SM9Ciphertext *ret = NULL;
	const EVP_MD *md;
	size_t size;
	size_t keylen;
	unsigned int mackeylen;
	unsigned int enckeylen;
	size_t cipherlen;

	if (!mpk || !msk || !id || idlen <= 0) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (strlen(id) != idlen || idlen > SM9_MAX_ID_LENGTH) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			SM9_R_INVALID_ID);
		return NULL;
	}

	/* malloc */
	ret = SM9PrivateKey_new();

	if (param->enc_cipher) {
		enckeylen = EVP_CIPHER_key_length(enc->enc_cipher);
	} else {
		enckeylen = inlen;
	}

	if (param->mac_cipher) {
		mackeylen = EVP_CIPEHR_key_length(enc->mac_cipher);
	} else if (param->hmac_md) {
		mackeylen = EVP_MD_size(enc->hmac_md);
	} else {
		goto end;
	}

	/* keylen = enckeylen + mackeylen */
	keylen = enckeylen + mackeylen;

	/* (enckey, mackey) = wrap_key() */
	if (!SM9_wrap_key(mpk, keylen, NULL, NULL, &cipherlen, id, idlen)) {
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(ret->pointC1, NULL, cipherlen)) {
	}
	if (!SM9_wrap_key(mpk, key, keylen, ret->pointC1->data, &cipherlen, id, idlen)) {
	}
	enckey = key;
	mackey = key + enckeylen;

	if (enc->enc_cipher) {
	} else {
		/* ret->c2 = enckey xor in */
		if (!ASN1_OCTET_STRING_set(ret->c2, NULL, inlen)) {
		}
		for (i = 0; i < inlen; i++) {
			ret->c2->data[i] = enckey[i] ^ in[i];
		}
	}

	if (enc->mac_cipher) {

	} else if (enc->hmac_md) {

		/* ret->c3 = HMAC(mackey, ret->c2) */
		unsigned char mac[EVP_MAX_MD_SIZE];
		unsigned int maclen;
		maclen = sizeof(mac);
		if (!HMAC(hmac_md, mackey, mackeylen, ret->c2->data, ret->c2->length,
			mac, &maclen)) {
		}
		if (!ASN1_OCTET_STRING_set(ret->c3, mac, maclen)) {
		}
	}


end:
	if (e && ret) {
		SM9PrivateKey_free(ret);
		ret = NULL;
	}
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	OPENSSL_free(buf);
	return NULL;


}

int SM9_do_decrypt(SM9PublicParameters *mpk,
	const SM9Ciphertext *in, unsigned char *out, size_t *outlen,
	SM9PrivateKey *sk)
{
	int ret = 0;

	if (!mpk || !msk || !id || idlen <= 0) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	if (strlen(id) != idlen || idlen > SM9_MAX_ID_LENGTH) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			SM9_R_INVALID_ID);
		return NULL;
	}

	/* BN_CTX */
	if (!(bn_ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(bn_ctx);

	/* EC_GROUP */
	if (!(group = EC_GROUP_new_type1curve_ex(mpk->p,
		mpk->a, mpk->b, mpk->pointP1->data, mpk->pointP1->length,
		mpk->order, mpk->cofactor, bn_ctx))) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, SM9_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* malloc */
	ret = SM9PrivateKey_new();
	point = EC_POINT_new(group);
	h = BN_CTX_get(bn_ctx);

	if (!ret || !point || !h) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* md = mpk->hashfcn */
	if (!(md = EVP_get_digestbyobj(mpk->hashfcn))) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY, SM9_R_INVALID_MD);
		goto end;
	}


				

	



end:
	
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(group);
	EC_POINT_free(point);
	EC_POINT_free(point1);
	BN_GFP2_free(w);
	OPENSSL_free(buf);

	SM9err(SM9_F_SM9_DO_DECRYPT, SM9_R_NOT_IMPLEMENTED);
	return 0;
}

int SM9_encrypt_with_recommended(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen, unsigned char *out,
	size_t *outlen, const char *id, size_t idlen)
{
	return 0;
}

int SM9_decrypt_with_recommended(SM9PublicParameters *mpk,
	const unsigned char *in, size_t inlen, unsigned char *out,
	size_t *outlen, SM9PrivateKey *sk)
{
	return 0;
}

