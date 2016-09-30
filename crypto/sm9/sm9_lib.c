/* crypto/sm9/sm9_lib.c */
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

//FIXME: not implemented
BIGNUM *SM9_hash1(const EVP_MD *md, const unsigned char *z, size_t zlen,
	const BIGNUM *range)
{
	int e = 1;
	BIGNUM *ret = NULL;

	if (!(ret = BN_new())) {
		SM9err(SM9_F_SM9_HASH1, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (!BN_set_word(ret, 123456)) {
		SM9err(SM9_F_SM9_HASH1, ERR_R_BN_LIB);
		goto end;
	}

	e = 0;
end:
	if (e && ret) {
		BN_free(ret);
		ret = NULL;
	}
	return ret;
}

//FIXME: not implemented
BIGNUM *SM9_hash2(const EVP_MD *md, const unsigned char *z, size_t zlen,
	const BINGUM *range)
{
	int e = 1;
	BIGNUM *ret = NULL;

	if (!(ret = BN_new())) {
		SM9err(SM9_F_SM9_HASH2, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (!BN_set_word(ret, 45678)) {
		SM9err(SM9_F_SM9_HASH2, ERR_R_BN_LIB);
		goto end;
	}

	e = 0;
end:
	if (e && ret) {
		BN_free(ret);
		ret = NULL;
	}
	return ret;
}

int SM9_check_group(const EC_GROUP *group)
{
	return 1;
}

