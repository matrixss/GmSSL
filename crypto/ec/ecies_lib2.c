/* crypto/ec/ecies_lib.c */
/* ====================================================================
 * Copyright (c) 2007 - 2016 The GmSSL Project.  All rights reserved.
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
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ecdh.h>
#include <openssl/kdf.h>
#include <openssl/ecies.h>
#include "internal/o_str.h"


int ECIES_PARAMS_init_with_recommended(ECIES_PARAMS *param)
{
	if (!param) {
		return 0;
	}
	param->kdf_nid = NID_x9_63_kdf;
	param->kdf_md = EVP_sha256();
	param->enc_nid = NID_xor_in_ecies;
	param->mac_nid = NID_hmac_full_ecies;
	param->hmac_md = EVP_sha256();
	return 1;
}

KDF_FUNC ECIES_PARAMS_get_kdf(const ECIES_PARAMS *param)
{
	if (!param || !param->kdf_md) {
		return NULL;
	}
	switch (param->kdf_nid) {
	case NID_x9_63_kdf:
		return KDF_get_x9_63(param->kdf_md);
	case NID_nist_concatenation_kdf:
	case NID_tls_kdf:
	case NID_ikev2_kdf:
		/* not implemented */
	}
	return NULL;
}

int ECIES_PARAMS_parse_enc(const ECIES_PARAMS *param, size_t inlen,
	const EVP_CIPHER **cipher, size_t *keylen, size_t *outlen)
{
	int ret = 0;
	size_t len = 0;

	if (!param || !cipher || !(*cipher) || !enckeylen || !outlen) {
		return 0;
	}

	len = inlen;

	switch (param->enc_nid) {
	case NID_xor_in_ecies:
		*enckeylen = inlen;
		break;
	case NID_tdes_cbc_in_ecies:
		*enc_cipher = EVP_des_ede_cbc();
		break;
	case NID_aes128_cbc_in_ecies:
		*enc_cipher = EVP_aes_128_cbc();
		break;
	case NID_aes192_cbc_in_ecies:
		*enc_cipher = EVP_aes_192_cbc();
		break;
	case NID_aes256_cbc_in_ecies:
		*enc_cipher = EVP_aes_256_cbc();
		break;
	case NID_aes128_ctr_in_ecies:
		*enc_cipher = EVP_aes_128_ctr();
		break;
	case NID_aes192_ctr_in_ecies:
		*enc_cipher = EVP_aes_192_ctr();
		break;
	case NID_aes256_ctr_in_ecies:
		*enc_cipher = EVP_aes_256_ctr();
		break;
	default:
		return 0;
	}

	if (param->enc_nid != NID_xor_in_ecies) {
		int blocksize;
		enckeylen = EVP_CIPHER_key_length(enc_cipher);
		blocksize = EVP_CIPHER_block_size(enc_cipher);
		if (random_iv) {
			cipherlen += blocksize;
		}
		if (EVP_CIPHER_mode(enc_cipher) == EVP_CIPH_CBC_MODE) {
			cipherlen += blocksize - inlen % blocksize;
		}
	}

	return 1;
}

int ECIES_PARAMS_get_mac(const ECIES_PARAMS *param, const EVP_CIPHER **cmac_cipher,
	unsigned int *mackeylen, unsigned int *maclen)
{
	switch (param->mac_nid) {
	case NID_hmac_full_ecies:
		mackeylen = EVP_MD_size(param->hmac_md);
		maclen = EVP_MD_size(param->hmac_md);
		break;
	case NID_hmac_half_ecies:
		mackeylen = EVP_MD_size(param->hmac_md);
		maclen = EVP_MD_size(param->hmac_md)/2;
		break;
	case NID_cmac_aes128_ecies:
		mac_cipher = EVP_aes_128_ecb();
		maclen = EVP_CIPHER_block_size(mac_cipher);
		break;
	case NID_cmac_aes192_ecies:
		mac_cipher = EVP_aes_192_ecb();
		maclen = EVP_CIPHER_block_size(mac_cipher);
		break;
	case NID_cmac_aes256_ecies:
		mac_cipher = EVP_aes_256_ecb();
		maclen = EVP_CIPHER_block_size(mac_cipher);
		break;
	default:
		ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_INVALID_ECIES_MAC_ALGOR);
		goto end;
	}

	return 1;
}

ECIES_CIPHERTEXT_VALUE *ECIES_do_encrypt(const ECIES_PARAMS *param,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
{
	int e = 1;
	KDF_FUNC kdf_func;
	const EVP_CIPHER *enc_cipher = NULL;
	unsigned int enckeylen, ciphertextlen;
	const EVP_CIPHER *mac_cipher = NULL;
	unsigned int mackeylen, maclen;
	ECIES_CIPHERTEXT_VALUE *ret = NULL;
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);
	EC_KEY *ephem_key = NULL;
	int point_form = POINT_CONVERSION_COMPRESSED;
	unsigned char *sharekey = NULL;
	unsigned int sharekeylen;
	unsigned char *enckey, *mackey;
	unsigned char mac[EVP_MAX_MD_SIZE];
	size_t len;

	if (!param || !in || !inlen || !ec_key || !group) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	/* parse parameters */
	if (!(kdf_func = ECIES_PARAMS_get_kdf(param))) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}
	if (!ECIES_PARAMS_get_enc(param, inlen, &enc_cipher, &enckeylen, &ciphertextlen)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}
	if (!ECIES_PARAMS_get_mac(param, &mac_cipher, &mackeylen, &maclen)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}

	/* malloc ciphertext value */
	if (!(ret = ECIES_CIPHERTEXT_VALUE_new())) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		return 0;
	}

	/* generate ephem keypair */
	if (!(ephem_key = EC_KEY_new())) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_KEY_set_group(ephem_key, group)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_KEY_generate_key(ephem_key)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* output ephem_point */
	len = EC_POINT_point2oct(group, EC_KEY_get0_public_key(ephem_key),
		point_form, NULL, 0, NULL);
	if (!ASN1_OCTET_STRING_set(ret->ephem_point, NULL, len)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_ASN1_LIB);
		goto end;
	}
	if (EC_POINT_point2oct(group, EC_KEY_get0_public_key(ephem_key),
		point_form, ret->ephem_point->data, len, NULL) <= 0) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_EC_LIB);
		goto end;
	}

	/* ecdh to generate enckey and mackey */
	sharekeylen = enckeylen + mackeylen;
	if (!(sharekey = OPENSSL_malloc(sharekeylen))) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
 	if (!ECDH_compute_key(sharekey, sharekeylen,
		EC_KEY_get0_public_key(ec_key), ephem_key,
		kdf_func)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_ECDH_FAILED);
		goto end;
	}
	enckey = sharekey;
	mackey = sharekey + enckeylen;

	/* encrypt */
	if (!ASN1_OCTET_STRING_set(cv->ciphertext, NULL, ciphertextlen)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (enc_cipher) {
		EVP_CIPHER_CTX *cipher_ctx = NULL;
		unsigned char ivbuf[EVP_MAX_IV_LENGTH];
		unsigned char *iv, *pout;
		unsigned int ivlen, len;

		ivlen = EVP_CIPHER_iv_length(enc_cipher);
		if (random_iv) {
			iv = ret->ciphertext->data;
			pout = ret->ciphertext->data + ivlen;
			RAND_bytes(iv, ivlen);
		} else {
			iv = ivbuf;
			pout = ret->ciphertext->data;
			memset(iv, 0, ivlen);
		}

		if (!(cipher_ctx = EVP_CIPHER_CTX_new())) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!EVP_EncryptInit(cipher_ctx, enc_cipher, enckey, iv)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_ENCRYPT_FAILED);
			EVP_CIPHER_CTX_free(cipher_ctx);
			goto end;
		}
		if (!EVP_EncryptUpdate(cipher_ctx, pout, &len, in, inlen)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_ENCRYPT_FAILED);
			EVP_CIPHER_CTX_free(cipher_ctx);
			goto end;
		}
		pout += len;
		if (!EVP_EncryptFinal(cipher_ctx, pout, &len)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_ENCRYPT_FAILED);
			goto end;
		}
		pout += len;

		OPENSSL_assert(p - cv->ciphertext->data == ciphertextlen);

	} else {
		unsigned int i;
		for (i = 0; i < ret->ciphertext->length; i++) {
			ret->ciphertext->data[i] = in[i] ^ enckey[i];
		}
	}

	/* generate mac */
	if (mac_cipher) {
		CMAC_CTX *cmac_ctx;
		if (!(cmac_ctx = CMAC_CTX_new())) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!CMAC_Init(cmac_ctx, mackey, mackeylen, cmac_cipher, NULL);
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_CMAC_INIT_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		if (!CMAC_Update(cmac_ctx, ret->ciphertext->data, ret->ciphertext->length)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_CMAC_UPDATE_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		len = sizeof(mac);
		if (!CMAC_Final(cmac_ctx, mac, &len)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_CMAC_FINAL_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		OPENSSL_assert(len == maclen);
		CMAC_CTX_free(cmac_ctx);

	} else {
		len = sizeof(mac);
		if (!HMAC(param->hmac_md, mackey, mackeylen,
			cv->ciphertext->data, cv->ciphertext->length,
			mac, &maclen)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_HMAC_FAILURE);
			goto end;
		}
		OPENSSL_assert(len == maclen || len/2 == maclen);
	}

	if (!ASN1_OCTET_STRING_set(cv->mactag, mac, maclen)) {
		ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}


	e = 0;
end:
	EC_KEY_free(ephem_key);
	OPENSSL_free(sharekey);
	if (e && ret) {
		ECIES_CIPHERTEXT_VALUE_free(ret);
		ret = NULL;
	}
	return ret;
}

int ECIES_do_decrypt(const ECIES_PARAMS *param, const ECIES_CIPHERTEXT_VALUE *in,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	EC_POINT *ephem_point = NULL;
	unsigned char *sharekey = NULL;
	unsigned char *enckey, *mackey;
	int sharelen, enckeylen, mackeylen, len;
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);

	if (!param || !in || !outlen || !ec_key) {
		ECerr(EC_F_ECIES_DO_DECRYPT, ERR_R_PASSED_INVALID_ARGUMENT);
		return 0;
	}

	if (!out) {
		*outlen = cv->ciphertext->length;
		return 1;
	}
	if (*outlen < cv->ciphertext->length) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}

	/* parse ephem_point */
	if (!in->ephem_point || !in->ephem_point->data || in->ephem_point->length <= 0) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
		goto end;
	}
	if (!(ephem_point = EC_POINT_new(group))) {
		ECerr(EC_F_ECIES_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EC_POINT_oct2point(group, ephem_point,
		in->ephem_point->data, in->ephem_point->length, NULL)) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
		goto end;
	}

	/* compute ecdh, get enckey and mackey */

	sharekeylen = enckeylen + mackeylen;
	if (!(sharekey = OPENSSL_malloc(sharekeylen))) {
		ECerr(EC_F_ECIES_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!(kdf_func = ECIES_PARAMS_get_kdf(param))) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_PARAMETERS);
		goto end;
	}
	if (!ECDH_compute_key(sharekey, sharekeylen, ephem_point, ec_key, kdf_func)) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_ECDH_FAILURE);
		goto end;
	}
	enckey = sharekey;
	mackey = sharekey + enckeylen;

	/*
	 * generate and verify mac
	 */

	if (!in->mactag || !in->mactag->data) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
		goto end;
	}

	if (param->hmac_md) {
		if (!HMAC(param->hmac_md, mackey, mackeylen,
			in->ciphertext->data, in->ciphertext->length,
			mac, &maclen)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_GEN_MAC_FAILED);
			goto end;
		}
	} else {
		CMAC_CTX *cmac_ctx;
		if (!(cmac_ctx = CMAC_CTX_new())) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!CMAC_Init(cmac_ctx, mackey, mackeylen, cmac_cipher, NULL);
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_CMAC_INIT_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		if (!CMAC_Update(cmac_ctx, in->ciphertext->data, in->ciphertext->length)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_CMAC_UPDATE_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		if (!CMAC_Final(cmac_ctx, mac, &maclen)) {
			ECerr(EC_F_ECIES_DO_ENCRYPT, EC_R_CMAC_FINAL_FAILURE);
			CMAC_CTX_free(cmac_ctx);
			goto end;
		}
		CMAC_CTX_free(cmac_ctx);
	}

	if (maclen != in->mactag->length) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_ECIES_VERIFY_MAC_FAILURE);
		goto end;
	}
	if (OPENSSL_memcmp(cv->mactag->data, mac, maclen)) {
		ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_ECIES_VERIFY_MAC_FAILURE);
		goto end;
	}

	/* decrypt */

	if (param->enc_nid == NID_xor_in_ecies) {
		unsigned int i;
		for (i = 0; i < in->ciphertext->length; i++) {
			out[i] = in->ciphertext->data[i] ^ enckey[i];
		}
		/* set final output length */
		*outlen = in->ciphertext->length;

	} else {
		unsigned int ivlen, inlen, len;
		unsigned char ivbuf[EVP_MAX_IV_LENGTH];
		unsigned char *iv, *pin, *pout;
		EVP_CIPEHR_CTX *cipher_ctx = NULL;

		/* prepare iv */
		ivlen = EVP_CIPHER_iv_length(enc_cipher);
		if (random_iv) {
			iv = in->ciphertext->data;
			pin = in->ciphertext->data + ivlen;
			if (in->ciphertext->length < ivlen) {
				ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
				goto end;
			}
			inlen = in->ciphertext->length - ivlen;

		} else {
			/* use fixed all-zero iv */
			memset(ivbuf, 0, ivlen);
			iv = ivbuf;
			pin = in->ciphertext->data;
			if (in->ciphertext->length <= 0) {
				ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_INVALID_ECIES_CIPHERTEXT);
				goto end;
			}
			inlen = in->ciphertext->length;
		}

		/* decrypt */
		if (!(cipher_ctx = EVP_CIPHER_CTX_new())) {
			ECerr(EC_F_ECIES_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
			goto end;
		}

		if (!EVP_DecryptInit(cipher_ctx, enc_cipher, enckey, iv)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_ECIES_DECRYPT_INIT_FAILURE);
			EVP_CIPHER_CTX_free(cipher_ctx);
			goto end;
		}
		pout = out;
		len = (unsigned int)*outlen; //FIXME: do we need to check it?

		if (!EVP_DecryptUpdate(cipher_ctx, pout, &len, pin, inlen)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_DECRYPT_FAILED);
			EVP_CIPHER_CTX_free(cipher_ctx);
			goto end;
		}
		pout += len;

		if (!EVP_DecryptFinal(cipher_ctx, pout, &len)) {
			ECerr(EC_F_ECIES_DO_DECRYPT, EC_R_DECRYPT_FAILED);
			EVP_CIPHER_CTX_free(cipher_ctx);
			goto end;
		}
		pout += len;

		EVP_CIPHER_CTX_free(cipher_ctx);
		/* set final output lenght */
		*outlen = pout - out;
	}

	r = 1;
err:
	if (share) OPENSSL_free(share);
	EVP_CIPHER_CTX_cleanup(&ctx);
	if (ephem_point) EC_POINT_free(ephem_point);

	return r;
}

int ECIES_encrypt(const ECIES_PARAMS *param,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	unsigned char *p = out;
	int len;

	if (!(cv = ECIES_do_encrypt(param, in, inlen, ec_key))) {
		ECerr(EC_F_ECIES_ENCRYPT, EC_R_ENCRYPT_FAILED);
		return 0;
	}

	if ((len = i2d_ECIES_CIPHERTEXT_VALUE(cv, NULL)) <= 0) {
		ECerr(EC_F_ECIES_ENCRYPT, EC_R_ENCRYPT_FAILED);
		goto end;
	}

	if (!out) {
		*outlen = (size_t)len;
		ret = 1;
		goto end;
	}

	if (*outlen < len) {
		ECerr(EC_F_ECIES_ENCRYPT, EC_R_ENCRYPT_FAILED);
		*outlen = (size_t)len;
		goto end;
	}

	if ((len = i2d_ECIES_CIPHERTEXT_VALUE(cv, &p)) <= 0) {
		ECerr(EC_F_ECIES_ENCRYPT, EC_R_ENCRYPT_FAILED);
		goto end;
	}

	*outlen = (size_t)len;
	ret = 1;

end:
	ECIES_CIPHERTEXT_VALUE_free(cv);
	return ret;
}


int ECIES_decrypt(const ECIES_PARAMS *param,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	ECIES_CIPHERTEXT_VALUE *cv = NULL;
	const unsigned char *p = in;

	if (!(cv = d2i_ECIES_CIPHERTEXT_VALUE(NULL, &p, (long)inlen))) {
		ECerr(EC_F_ECIES_DECRYPT, EC_R_ENCRYPT_FAILED);
		return 0;
	}

	if (!ECIES_do_decrypt(cv, param, out, outlen, ec_key)) {
		ECerr(EC_F_ECIES_DECRYPT, EC_R_ENCRYPT_FAILED);
		goto end;
	}

	ret = 1;
end:
	ECIES_CIPHERTEXT_VALUE_free(cv);
	return ret;
}


int ECIES_encrypt_with_recommended(const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	ECIES_PARAMS param;
	ECIES_PARAMS_init_with_recommended(&param);
	return ECIES_encrypt(&param, in, inlen, out, outlen, ec_key);
}

int ECIES_decrypt_with_recommended(const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	ECIES_PARAMS param;
	ECIES_PARAMS_init_with_recommended(&param);
	return ECIES_decrypt(&param, in, inlen, out, outlen, ec_key);
}

