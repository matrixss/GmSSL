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
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/pairing.h>

ASN1_SEQUENCE(FpPoint) = {
	ASN1_SIMPLE(FpPoint, x, BIGNUM),
	ASN1_SIMPLE(FpPoint, y, BIGNUM)
} ASN1_SEQUENCE_END(FpPoint)
IMPLEMENT_ASN1_FUNCTIONS(FpPoint)
IMPLEMENT_ASN1_DUP_FUNCTION(FpPoint)


typedef struct {
	int security_bits;
	int n_bits;
	int p_bits;
	int q_bits;
} PAIRING_SEC;

static PAIRING_SEC sec_tbl[] = {
	/* k    |n|   |p|  |q| */
	{ 80,  1024,  512, 160},
	{112,  2048, 1024, 224},
	{128,  3072, 1536, 256},
	{192,  7680, 3840, 384},
	{256, 15360, 7680, 512}
};

const EVP_MD *PAIRING_nbits_to_md(int nbits)
{
	switch (bits) {
	case 1024: return EVP_sha1();
	case 2048: return EVP_sha224();
	case 3072: return EVP_sha256();
	case 7680: return EVP_sha384();
	case 15360: return EVP_sha512();
	}
	return NULL;
}

int PAIRING_hash_bytes(const EVP_MD *md, const char *s, size_t slen,
	size_t outlen, unsigned char *out)
{
	return 0;
}

int PAIRING_hash_to_point_GFp(PAIRING *pairing, const EVP_MD *md,
	const char *id, size_t idlen, EC_POINT *point, BN_CTX *ctx)
{
	return 0;
}

int PAIRING_hash_to_point_GFp2(PAIRING *pairing, const EVP_MD *md,
	const char *id, size_t idlen, EC_POINT_GFP2 *point, BN_CTX *ctx)
{
	return 0;
}

int BN_hash2bn(BIGNUM **bn, const char *s, size_t slen,
	const EVP_MD *md, const BIGNUM *range)
{
	int ret = 0;
	BIGNUM *r = NULL;
	BIGNUM *a = NULL;
	BN_CTX *bn_ctx = NULL;
	unsigned char *buf = NULL;
	size_t buflen, mdlen;
	int nbytes, rounds, i;

	if (!s || slen <= 0 || !md || !range) {
		BNerr(BN_F_BN_HASH2BN, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(*bn)) {
		if (!(r = BN_new())) {
			BNerr(BN_F_BN_HASH2BN, ERR_R_MALLOC_FAILURE);
			return 0;
		}
	} else {
		r = *bn;
		BN_zero(r);
	}

	mdlen = EVP_MD_size(md);
	buflen = mdlen + slen;
	if (!(buf = OPENSSL_malloc(buflen))) {
		BNerr(BN_F_BN_HASH2BN, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	memset(buf, 0, mdlen);
	memcpy(buf + mdlen, s, slen);

	a = BN_new();
	bn_ctx = BN_CTX_new();
	if (!a || !bn_ctx) {
		BNerr(BN_F_BN_HASH2BN, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	nbytes = BN_num_bytes(range);
	rounds = (nbytes + mdlen - 1)/mdlen;

	if (!bn_expand(r, rounds * mdlen * 8)) {
		BNerr(BN_F_BN_HASH2BN, ERR_R_BN_LIB);
		goto end;
	}

	for (i = 0; i < rounds; i++) {
		if (!EVP_Digest(buf, buflen, buf, (unsigned int *)&mdlen, md, NULL)) {
			BNerr(BN_F_BN_HASH2BN, ERR_R_EVP_LIB);
			goto end;
		}
		if (!BN_bin2bn(buf, mdlen, a)) {
			BNerr(BN_F_BN_HASH2BN, ERR_R_BN_LIB);
			goto end;
		}
		if (!BN_lshift(r, r, mdlen * 8)) {
			BNerr(BN_F_BN_HASH2BN, ERR_R_BN_LIB);
			goto end;
		}
		if (!BN_uadd(r, r, a)) {
			goto end;
		}
	}

	if (!BN_mod(r, r, range, bn_ctx)) {
		BNerr(BN_F_BN_HASH2BN, ERR_R_BN_LIB);
		goto end;
	}

	*bn = r;
	ret = 1;
end:
	if (!ret && !(*bn)) {
		BN_free(r);
	}
	BN_free(a);
	BN_CTX_free(bn_ctx);
	OPENSSL_free(buf);
	return ret;
}

#if 1
int main(void)
{
	char *s = "This ASCII string without null-terminator";
	BIGNUM *bn = NULL;
	BIGNUM *ret = NULL;
	BIGNUM *range = NULL;

	BN_hex2bn(&range, "ffffffffffffffffffffefffffffffffffffffff");
	BN_hex2bn(&bn, "79317c1610c1fc018e9c53d89d59c108cd518608");

	if (!BN_hash2bn(&ret, s, strlen(s), EVP_sha1(), range)) {
		printf("BN_hash2bn() function failed\n");
		return 0;
	}
	if (!ret) {
		printf("shit\n");
	}
	printf("%s\n", BN_bn2hex(ret));
	if (BN_cmp(ret, bn) != 0) {
		printf("BN_hash2bn() test failed\n");
		return 0;
	}

	printf("BN_hash2bn() test passed\n");
	return 1;
}
#endif



/*
 * solinas = 2^a + s * 2^b + c, where s, c in {1, -1}
 * solinas looks like:
 *   2^a + 2^b + 1 = 10000100001
 *   2^a - 2^b + 1 =  1111100001
 *   2^a + 2^b - 1 = 10000011111
 *   2^a - 2^b - 1 =  1111011111
 * so:
 *   n = len(bits(solinas))
 *   c = bits(solinas)[1] == 0 ? 1 : -1
 *   s = bits(solinas)[n-2] == 0 ? 1 : -1
 *   a = bits(solinas)[n-2] == 0 ? n-1 : n-2
 *   b = len(bits(solinas - 2^a - s*2^b - c)) - 1
 *
 * examples:
 *   0xfffffffffffffffffffffffffffbffff
 *   0xffffffffffffffffffffffeffffffffffff
 *   0xfffffffffbfffffffffffffffffffffffff
 */


int BN_bn2solinas(const BIGNUM *bn, BN_SOLINAS *solinas)
{
	int ret = 0;
	BIGNUM *tmp = NULL;
	int nbits;

	if (!solinas || !bn) {
		BNerr(BN_F_BN_BN2SOLINAS, ERR_R_PASSED_NULL_PARAMTERSs);
		return 0;
	}

	if (!BN_copy(tmp, bn)) {
		goto end;
	}

	if ((n = BN_num_bits(bn) - 1) < 1) {
		BNerr(BN_F_BN_BN2SOLINAS, BN_R_INVALID_SOLINAS);
		goto end;
	}

	solinas->c = BN_is_bit_set(bn, 1) ? 1 : -1;
	if (BN_is_bit_set(bn, n-1)) {
		s = -1;
		a = n;
	} else {
		s = 1;
		a = n-1;
	}

	for (i = 1; i < n; i++) {
	}

	return 0;
}

int BN_solinas2bn(const BN_SOLINAS *solinas, BIGNUM *bn)
{
	int ret = 0;
	BIGNUM *tmp = NULL;
#if 0
	if (b <= 0 || a <= b || (s != 1 && s != -1) ||
		(c != 1 && c != -1)) {
		BNerr(BN_F_BN_SOLINAS2BN, BN_R_INVALID_SOLINAS_PARAMETERS);
		return 0;
	}

	if (!(tmp = BN_new())) {
		BNerr(BN_F_BN_SOLINAS2BN, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	BN_one(tmp);

	if (!BN_lshift(solinas, tmp, a)) {
		BNerr(BN_F_BN_SOLINAS2BN, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_lshift(tmp, tmp, b)) {
		BNerr(BN_F_BN_SOLINAS2BN, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_add_word(tmp, c)) {
		BNerr(BN_F_BN_SOLINAS2BN, ERR_R_BN_LIB);
		goto end;
	}
	if (s > 0) {
		if (!BN_add(solinas, solinas, tmp)) {
			BNerr(BN_F_BN_SOLINAS2BN, ERR_R_BN_LIB);
			goto end;
		}
	} else {
		if (!BN_sub(solinas, solinas, tmp)) {
			BNerr(BN_F_BN_SOLINAS2BN, ERR_R_BN_LIB);
			goto end;
		}
	}

	/* check if solinas is a prime */

	ret = 1;
end:
	BN_free(tmp);
#endif
	return ret;
}

int BN_is_solinas(const BIGNUM *a)
{
	return 0;
}

PAIRING *PAIRING_new_type1(const BIGNUM *p, const BIGNUM *q, const FpPoint *P)
{
	return NULL;
}

/*
   Canonical(p, k, o, v) takes an element v in F_p^k, and returns a
   canonical octet string of fixed length representing v.  The parameter
   o MUST be either 0 or 1, and specifies the ordering of the encoding.
*/

int BN_GFP2_canonical(const BN_GFP2 *v, unsigned char *out, size_t *outlen,
	int order, const BIGNUM *p)
{
	return 0;
}


