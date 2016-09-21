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
 *
 */


#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#define EC_MAX_NBYTES  ((OPENSSL_ECC_MAX_FIELD_BITS + 7)/8)


int SM2_get_public_key_data(EC_KEY *ec_key, unsigned char *out, size_t *outlen)
{
	int ret = 0;
	const EC_GROUP *ec_group;
	const EC_POINT *point;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	unsigned char oct[EC_MAX_NBYTES * 2 + 1];
	int nbytes;
	size_t len;

	if (!ec_key || !outlen) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	ec_group = EC_KEY_get0_group(ec_key);
	nbytes = (EC_GROUP_get_degree(ec_group) + 7)/8;
	len = nbytes * 6;

	if (!out) {
		*outlen = len;
		return 1;
	}
	if (*outlen < len) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}

	memset(out, 0, len);

	bn_ctx = BN_CTX_new();
	p = BN_new();
	x = BN_new();
	y = BN_new();
	if (!bn_ctx || !p || !x || !y) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA,  ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* get curve coefficients */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == NID_X9_62_prime_field) {
		if (!EC_GROUP_get_curve_GFp(ec_group, p, x, y, bn_ctx)) {
			ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
			goto end;
		}
	} else {
		if (!EC_GROUP_get_curve_GF2m(ec_group, p, x, y, bn_ctx)) {
			ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
			goto end;
		}
	}

	out += nbytes;
	if (!BN_bn2bin(x, out - BN_num_bytes(x))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_BN_LIB);
		goto end;
	}
	out += nbytes;
	if (!BN_bn2bin(y, out - BN_num_bytes(y))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_BN_LIB);
		goto end;
	}

	/* get curve generator coordinates */
	if (!(point = EC_GROUP_get0_generator(ec_group))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
		goto end;
	}
	if (!(len = EC_POINT_point2oct(ec_group, point,
		POINT_CONVERSION_UNCOMPRESSED, oct, sizeof(oct), bn_ctx))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
		goto end;
	}
	memcpy(out, oct + 1, len - 1);
	out += len - 1;

	/* get pub_key coorindates */
	if (!(point = EC_KEY_get0_public_key(ec_key))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
		goto end;
	}
	if (!(len = EC_POINT_point2oct(ec_group, point,
		POINT_CONVERSION_UNCOMPRESSED, oct, sizeof(oct), bn_ctx))) {
		ECerr(EC_F_SM2_GET_PUBLIC_KEY_DATA, ERR_R_EC_LIB);
		goto end;
	}
	memcpy(out, oct + 1, len - 1);
	out += len - 1;

	ret = 1;
end:
	BN_free(p);
	BN_free(x);
	BN_free(y);
	BN_CTX_free(bn_ctx);
	return ret;
}

int SM2_compute_id_digest(unsigned char *dgst, const EVP_MD *md,
	const char *id, EC_KEY *ec_key)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char idbits[2];
	unsigned char pkdata[(EC_MAX_NBYTES + 1) * 6];
	size_t pkdatalen;
	unsigned int dgstlen;

	if (EVP_MD_size(md) != SM2_ID_DIGEST_LENGTH) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, EC_R_INVALID_DIGEST_ALGOR);
		goto end;
	}

	if (strlen(id) > SM2_MAX_ID_LENGTH) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, EC_R_INVALID_ID_LENGTH);
		goto end;
	}

	pkdatalen = sizeof(pkdata);
	if (!SM2_get_public_key_data(ec_key, pkdata, &pkdatalen)) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, EC_R_GET_PUBLIC_KEY_DATA_FAILURE);
		goto end;
	}

	idbits[0] = ((strlen(id) * 8) >> 8) % 256;
	idbits[1] = (strlen(id) * 8) % 256;

	if (!(md_ctx = EVP_MD_CTX_create())) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, idbits, sizeof(idbits))) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, id, strlen(id))) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_DigestUpdate(md_ctx, pkdata, pkdatalen)) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}
	dgstlen = SM2_ID_DIGEST_LENGTH;
	if (!EVP_DigestFinal_ex(md_ctx, dgst, &dgstlen)) {
		ECerr(EC_F_SM2_COMPUTE_ID_DIGEST, ERR_R_EVP_LIB);
		goto end;
	}

	ret = 1;

end:
	EVP_MD_CTX_destroy(md_ctx);
        return ret;
}

