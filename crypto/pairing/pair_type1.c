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
#include <openssl/bn_gfp2.h>


int PAIRING_eval_vertical_GFp2(BN_GFP2 *r,
	const GFP2_POINT *B, const EC_POINT *A,
	const EC_GROUP *group, const BIGNUM *p, BN_CTX *ctx)
{
	BN_GFP2_sub(r, B->x, A->x, p, ctx);
	return 1;
}

int PAIRING_eval_tangent(BN_GFP2 *r, const GFP2_POINT *B,
	const GFP2_POINT *A, const BIGNUM *p, BN_CTX *ctx)
{
	if (GFP2_POINT_is_zero(A)) {
		BN_GFP2_one(r);
		return 1;
	}

	if (BN_GFP2_is_zero(A->y)) {
		EvalVertical(r, B, A, p, ctx);
		return 1;
	}

	BN_GFP2 *a = BN_GFP2_new();
	BN_GFP2 *b = BN_GFP2_new();
	BN_GFP2 *c = BN_GFP2_new();
	BN_GFP2 *t = BN_GFP2_new();

	BN_GFP2_sqr(a, A->x, p, ctx);
	BN_GFP2_add(b, a, a, p, ctx);
	BN_GFP2_add(a, a, b, p, ctx);
	BN_GFP2_neg(a, a, p, ctx);

	BN_GFP2_add(b, A->y, A->y, p, ctx);

	BN_GFP2_mul(c, b, B->x, p, ctx);
	BN_GFP2_mul(t, a, A->x, p, ctx);
	BN_GFP2_add(c, c, t, p, ctx);
	BN_GFP2_neg(c, c, p, ctx);

	BN_GFP2_mul(a, a, B->x, p, ctx);
	BN_GFP2_mul(b, b, B->y, p, ctx);
	BN_GFP2_add(r, a, b, p, ctx);
	BN_GFP2_add(r, r, c, p, ctx);

	BN_GFP2_free(a);
	BN_GFP2_free(b);
	BN_GFP2_free(c);
	BN_GFP2_free(t);
	return 1;
}

int PAIRING_eval_line_GFp2(BN_GFP2 *r, const EC_POINT_GFP2 *B,
	const EC_POINT_GFP2 *A, const BIGNUM *p, BN_CTX *ctx)
{
	PAIRINGerr(PAIRING_F_PAIRING_EVAL_LINE_GFP2, PAIRING_R_NOT_IMPLEMENTED);
	return 0;
}


/* phi: (x, y) => (zeta * x, y) */
int PAIRING_phi_GFp2(EC_POINT_GFP2 *R, const EC_POINT *P,
	const BN_GFP2 *zeta, const BIGNUM *p, BN_CTX *ctx)
{
	int ret = 0;
	const EC_GROUP *group;
	const BN_GFP2 *zeta;
	BIGNUM *p = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	if (!R || !P || !ctx) {
		PAIRINGerr(PAIRING_F_PAIRING_PHI_GFP2, ERR_R_PASSED_NULL_PARAMETERS);
		return 0;
	}

	group = PAIRING_get0_group(pairing);
	zeta = PAIRING_get0_zeta(pairing);

	p = BN_new();
	x = BN_new();
	y = BN_new();
	if (!x || !y) {
		PAIRINGerr(PAIRING_F_PAIRING_PHI_GFP2, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!PAIRING_get_order(pairing, &p, ctx)) {
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) {
		PAIRINGerr(PAIRING_F_PAIRING_PHI_GFP2, ERR_R_EC_LIB);
		goto end;
	}

	/* phi((x, y)) return (zeta * x, y) */
	if (!BN_GFP2_mul_bn(R->x, zeta, x, p, ctx)) {
		PAIRINGerr(PAIRING_F_PAIRING_PHI_GFP2, PAIRING_R_BN_GFP2_FAILURE);
		goto end;
	}
	if (!BN_GFP2_set_bn(R->y, y, p, ctx)) {
		PAIRINGerr(PAIRING_F_PAIRING_PHI_GFP2, PAIRING_R_BN_GFP2_FAILURE);
		goto end;
	}

	ret = 1;

end:
	BN_free(p);
	BN_free(x);
	BN_free(y);
	return ret;
}

int PAIRING_eval_miller_GFp2(PAIRING *pairing, BN_GFP2 *r,
	const EC_POINT *P, const EC_POINT *Q, BN_CTX *ctx)
{
	int ret = 0;
	EC_POINT_GFP2 *Q2 = NULL;
	BIGNUM *eta;
	BIGNUM *p;

	group = PAIRING_get0_group(pairing);
	eta = PAIRING_get0_eta(pairing);
	p = PAIRING_get0_order(pairing);


	if (!(Q2 = EC_POINT_GFP2_new())) {
		PAIRINGerr(PAIRING_F_PAIRING_EVAL_MILLER_GFP2, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* compute e(P, phi(Q))^eta */
	if (!PAIRING_phi_GFp2(pairing, Q2, Q, ctx)) {
		PAIRINGerr(PAIRING_F_PAIRING_EVAL_MILLER_GFP2, PAIRING_R_PHI_FAILURE);
		goto end;
	}
	if (!PAIRING_eval_miller_GFP2(pairing, r, P, Q2, ctx)) {
		PAIRINGerr(PAIRING_F_PAIRING_EVAL_MILLER_GFP2, PAIRING_R_MILLER_FAILURE);
		goto end;
	}
	if (!BN_GFP2_exp(r, r, eta, p, ctx)) {
		PAIRINGerr(PAIRING_F_PAIRING_EVAL_MILLER_GFP2, PAIRING_R_BN_GFP2_FAILURE);
		goto end;
	}


	ret = 1;

end:
	EC_POINT_GFP2_free(Q2);
	return ret;
}
