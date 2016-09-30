/* crypto/sm9/sm9_genkey.c */
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

/*
 Given user identity ID,

 1. Compute t1 = H1(ID||hid, N) + ks. If t1 == 0 then return "Failed"
 2. Compute t2 = ks * t1^{-1} mod N
 3. Compute ds = [t2]P1
 */

SM9PrivateKey *SM9_extract_private_key(SM9PublicParameters *mpk,
	SM9MasterSecret *msk, const char *id, size_t idlen)
{
	int e = 1;
	SM9PrivateKey *ret = NULL;
	BIGNUM *N = NULL;
	BIGNUM *t1 = NULL;


	if (!mpk || !msk || !id || idlen <= 0) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			ERR_R_PASSED_NULL_PARAMETERS);
		return NULL;
	}

	if (!(ret = SM9PrivateKey_new())) {
		SM9err(SM9_F_SM9_EXTRACT_PRIVATE_KEY,
			ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (!(t1 = SM9_hash1(id, idlen, N))) {
		goto end;
	}
	if (!BN_add(t1, t1, N)) {
		goto end;
	}
	if (BN_is_zero(t1)) {
		goto end;
	}

	if (!BN_mod_inverse(t1, t1, N, bn_ctx)) {
		goto end;
	}

	if (!BN_mod_mul(t2, t1, ks, N, bn_ctx)) {
		goto end;
	}

	if (!EC_POINT_mul(group, mks->sk, NULL, t2, P1, bn_ctx)) {
		goto end;
	}

	e = 0;
end:
	return ret;
}

