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

int SM9_setup(int curve, SM9PublicParameters **mpk, SM9MasterSecret **msk)
{
	int ret = 0;
	SM9PublicParameters *pk = NULL;
	SM9MasterSecret *sk = NULL;
	EC_GROUP *group = NULL;
	BIGNUM *order = NULL;
	EC_POINT *Ppub = NULL;
	BN_CTX *bn_ctx = NULL;

	pk = SM9PublicParameters_new();
	sk = SM9MasterSecret_new();
	group = EC_GROUP_new_by_curve_name(curve);
	order = BN_new();
	bn_ctx = BN_CTX_new();
	if (!pk || !sk || !order || !bn_ctx) {
		SM9err(SM9_F_SM9_SETUP, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!(group = EC_GROUP_new_by_curve_name(curve))) {
		SM9err(SM9_F_SM9_SETUP, SM9_R_UNKNOWN_CURVE);
		goto end;
	}
	if (!SM9_check_group(group)) {
		SM9err(SM9_F_SM9_SETUP, SM9_R_INVALID_CURVE);
		goto end;
	}
	OPENSSL_assert(pk->curve == NULL);
	pk->curve = OBJ_nid2obj(curve);

	if (!EC_GROUP_get_order(group, order, bn_ctx)) {
		SM9err(SM9_F_SM9_SETUP, ERR_R_EC_LIB);
		goto end;
	}
	OPENSSL_assert(sk->ks != NULL);
	do {
		if (!BN_rand_range(sk->ks, order)) {
			SM9err(SM9_F_SM9_SETUP, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(sk->ks));

	if (!EC_GROUP_mul(group, point, NULL, sk->ks, NULL, bn_ctx)) {
		SM9err(SM9_F_SM9_SETUP, ERR_R_EC_LIB);
		goto end;
	}
	//FIXME: see EC_GROUP_get_ecparameters() in ec_asn1.c

	*mpk = pk;
	*msk = sk;
	ret = 1;

end:
	if (!ret) {
		SM9PublicParameters_free(pk);
		SM9MasterSecret_free(sk);
		*mpk = NULL;
		*msk = NULL;
	}
	EC_GROUP_free(group);
	EC_POINT_free(point);
	BN_free(order);
	BN_CTX_free(bn_ctx);
	return ret;
}

