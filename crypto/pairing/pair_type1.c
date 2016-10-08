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
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn_gfp2.h>
#include <openssl/ec_type1.h>
#include <openssl/pairing.h>

/* phi: (x, y) => (zeta * x, y) */
static int type1curve_phi(const EC_GROUP *group, const EC_POINT *point,
	BN_GFP2 *x, BN_GFP2 *y, const BIGNUM *p, BN_CTX *bn_ctx)
{
	int ret = 0;
	BN_GFP2 *zeta = NULL;
	BIGNUM *xP;
	BIGNUM *yP;

	if (!group || !point || !x || !y || !p || !bn_ctx) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_PHI, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	BN_CTX_start(bn_ctx);
	xP = BN_CTX_get(bn_ctx);
	yP = BN_CTX_get(bn_ctx);

	if (!xP || !yP) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_PHI, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!(zeta = EC_GROUP_get_type1curve_zeta(group, bn_ctx))) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_PHI, PAIRING_R_GET_TYPE1CURVE_ZETA_FAILURE);
		goto end;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, point, xP, yP, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_PHI, ERR_R_EC_LIB);
		goto end;
	}

	/* return x = zeta * point->x */
	if (!BN_GFP2_mul_bn(x, zeta, xP, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_PHI, ERR_R_BN_LIB);
		goto end;
	}

	/* return y = point->y */
	if (!BN_GFP2_set_bn(y, yP, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_PHI, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;

end:
	BN_CTX_end(bn_ctx);
	BN_GFP2_free(zeta);
	return ret;
}

/*
 * eval the function defined by the line through point T and P,
 * with value Q = (xQ, yQ)
 */
static int type1curve_eval_line_textbook(const EC_GROUP *group, BN_GFP2 *r,
	const EC_POINT *T, const EC_POINT *P, const BN_GFP2 *xQ, const BN_GFP2 *yQ,
	BN_CTX *bn_ctx)
{
	int ret = 0;
	BN_GFP2 *num = NULL;
	BN_GFP2 *den = NULL;
	BIGNUM *p;
	BIGNUM *xT;
	BIGNUM *yT;
	BIGNUM *xP;
	BIGNUM *yP;
	BIGNUM *bn;
	BIGNUM *slope;

	if (!group || !r || !T || !P || !xQ || !yQ || !bn_ctx) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	BN_CTX_start(bn_ctx);
	p = BN_CTX_get(bn_ctx);
	xT = BN_CTX_get(bn_ctx);
	yT = BN_CTX_get(bn_ctx);
	xP = BN_CTX_get(bn_ctx);
	yP = BN_CTX_get(bn_ctx);
	bn = BN_CTX_get(bn_ctx);
	slope = BN_CTX_get(bn_ctx);

	num = BN_GFP2_new();
	den = BN_GFP2_new();

	if (!p || !xT || !yT || !xP || !yP || !bn || !slope || !num || !den) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	/* get prime field p */
	if (!EC_GROUP_get_curve_GFp(group, p, xT, yT, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_EC_LIB);
		goto end;
	}

	/* get T and P */
	if (!EC_POINT_get_affine_coordinates_GFp(group, T, xT, yT, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_EC_LIB);
		goto end;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, P, xP, yP, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_EC_LIB);
		goto end;
	}

#if 0
	/* if T == P, slope = (3 * x_T^2 + a)/(2 * y_T) */
	if (T == P || (BN_cmp(xT, xP) == 0  && BN_cmp(yT, yP) == 0)) {

		if (!BN_mod_sqr(bn, xT, p, bn_ctx)) {
			goto end;
		}
		if (!BN_mod_add(slope, bn, bn, p, bn_ctx)) {
			goto end;
		}
		if (!BN_mod_add(slope, slope, bn, p, bn_ctx)) {
			goto end;
		}
		if (!BN_mod_add(den, yT, yT, p, bn_ctx)) {
			goto end;
		}
		if (!BN_mod_inverse(den, den, p, bn_ctx)) {
			goto end;
		}
		if (!BN_mod_mul(slope, slope, den, p, bn_ctx)) {
			goto end;
		}
	}

	/*
	 * if xT == xP and yT + yP == 0, return xQ - xT
	 */

	if (BN_cmp(xT, xP) == 0) {
		BIGNUM *t;
		if (!(t = BN_CTX_get(bn_ctx))) {
			goto end;
		}
		if (!BN_mod_add(t, yT, yP, p, ctx)) {
			goto end;
		}
		if (BN_is_zero(t)) {
			if (!BN_GFP2_sub_bn(r, xQ, xT, p, bn_ctx)) {
				goto end;
			}
		}
	}

	/*
	 * if T == P, slope = (3 * x_T^2 + a)/(2 * y_T)
	 * else slope = (y_T - y_P)/(x_T - x_P)
	 */
	if (!BN_mod_sub(num, yT, yP, p, bn_ctx)) {
		goto end;
	}
	if (!BN_mod_sub(den, xT, xP, p, bn_ctx)) {
		goto end;
	}
	if (!BN_mod_inverse(den, den, p, bn_ctx)) {
		goto end;
	}
	if (!BN_mod_mul(slope, num, den, p, bn_ctx)) {
		goto end;
	}
#endif

	/*
	 * num = (yQ - ((xQ - xT) * slope)) - yT
	 * den = xQ + (xT + (xP - slope^2))
	 * return  num/den
	 */

	if (!BN_GFP2_sub_bn(num, xQ, xT, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_GFP2_mul_bn(num, num, slope, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_GFP2_sub(num, yQ, num, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_GFP2_sub_bn(num, num, yT, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}

	if (!BN_mod_sqr(bn, slope, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_sub(bn, xP, bn, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_mod_add(bn, xT, bn, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_GFP2_add_bn(den, xQ, bn, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}


	if (!BN_GFP2_div(ret, num, den, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_LINE_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}

	ret = 1;

end:
	BN_CTX_end(bn_ctx);
	BN_GFP2_free(num);
	BN_GFP2_free(den);
	return ret;
}

static int type1curve_eval_miller_textbook(const EC_GROUP *group, BN_GFP2 *r,
	const EC_POINT *P, const BN_GFP2 *xQ, const BN_GFP2 *yQ,
	const BIGNUM *p, BN_CTX *bn_ctx)
{
	int ret = 0;
	BN_GFP2 *f = NULL;
	BN_GFP2 *g = NULL;
	EC_POINT *T = NULL;
	BIGNUM *n;
	int nbits;
	int i;

	if (!group || !r || !P || !xQ || !yQ || !p || !bn_ctx) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	BN_CTX_start(bn_ctx);
	n = BN_CTX_get(bn_ctx);

	f = BN_GFP2_new();
	g = BN_GFP2_new();
	T = EC_POINT_new(group);

	if (!n || !f || !g || !T) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!EC_GROUP_get_order(group, n, bn_ctx)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_EC_LIB);
		goto end;
	}

	nbits = BN_num_bits(n);

	/* miller loop */
	for (i = nbits - 2; i >= 0; i--) {

		/* f = f^2 */
		if (!BN_GFP2_sqr(f, f, p, bn_ctx)) {
			PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_BN_LIB);
			goto end;
		}

		/* compute g_{T,T}(Q) */
		if (!type1curve_eval_line_textbook(group, g, T, T, xQ, yQ, bn_ctx)) {
			PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_PAIRING_LIB);
			goto end;
		}

		/* f = f * g */
		if (!BN_GFP2_mul(f, f, g, p, bn_ctx)) {
			PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_BN_LIB);
			goto end;
		}

		/* T = 2T */
		if (!EC_POINT_dbl(group, T, T, bn_ctx)) {
			PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_EC_LIB);
			goto end;
		}

		if (BN_is_bit_set(n, i)) {

			/* g = g_{T,P}(Q) */
			if (!type1curve_eval_line_textbook(group, g, T, P, xQ, yQ, bn_ctx)) {
				PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_PAIRING_LIB);
				goto end;
			}

			/* f = f * g */
			if (!BN_GFP2_mul(f, f, g, p, bn_ctx)) {
				PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_BN_LIB);
				goto end;
			}

			/* T = T + P */
			if (!EC_POINT_add(group, T, T, P, bn_ctx)) {
				PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_EC_LIB);
				goto end;
			}
		}
	}

	/* set return value */
	if (!BN_GFP2_copy(r, f)) {
		PAIRINGerr(PAIRING_F_TYPE1CURVE_EVAL_MILLER_TEXTBOOK, ERR_R_BN_LIB);
		goto end;
	}
	ret = 1;

end:
	BN_CTX_end(bn_ctx);
	BN_GFP2_free(f);
	BN_GFP2_free(g);
	EC_POINT_free(T);
	return ret;
}

int PAIRING_type1curve_tate(const EC_GROUP *group, BN_GFP2 *r,
	const EC_POINT *P, const EC_POINT *Q, BN_CTX *bn_ctx)
{
	int ret = 0;
	BN_GFP2 *xQ = NULL;
	BN_GFP2 *yQ = NULL;
	BIGNUM *eta = NULL;
	BIGNUM *p;
	BIGNUM *a;
	BIGNUM *b;

	if (!group || !ret || !P || !Q || !bn_ctx) {
		PAIRINGerr(PAIRING_F_PAIRING_TYPE1CURVE_TATE,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	BN_CTX_start(bn_ctx);

	xQ = BN_GFP2_new();
	yQ = BN_GFP2_new();
	p = BN_CTX_get(bn_ctx);
	a = BN_CTX_get(bn_ctx);
	b = BN_CTX_get(bn_ctx);

	if (!xQ || !yQ || !p || !a || !b) {
		PAIRINGerr(PAIRING_F_PAIRING_TYPE1CURVE_TATE, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if (!EC_GROUP_get_curve_GFp(group, p, a, b, bn_ctx)) {
		PAIRINGerr(PAIRING_F_PAIRING_TYPE1CURVE_TATE, PAIRING_R_INVALID_TYPE1CURVE);
		goto end;
	}

	/* (xQ, yQ) = phi(Q) */
	if (!type1curve_phi(group, Q, xQ, yQ, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_PAIRING_TYPE1CURVE_TATE, ERR_R_PAIRING_LIB);
		goto end;
	}

	/* compute e(P, phi(Q)) */
	if (!type1curve_eval_miller_textbook(group, r, P, xQ, yQ, p, bn_ctx)) {
		PAIRINGerr(PAIRING_F_PAIRING_TYPE1CURVE_TATE, ERR_R_PAIRING_LIB);
		goto end;
	}

	/* compute e(P, phi(Q))^eta, eta = (p^2 - 1)/q */
	if (!(eta = EC_GROUP_get_type1curve_eta(group, bn_ctx))) {
		PAIRINGerr(PAIRING_F_PAIRING_TYPE1CURVE_TATE, PAIRING_R_INVALID_TYPE1CURVE);
		goto end;
	}

	ret = 1;

end:
	BN_GFP2_free(xQ);
	BN_GFP2_free(yQ);
	BN_CTX_end(bn_ctx);
	BN_free(eta);
	return ret;
}

int PAIRING_type1curve_tate_ratio(const EC_GROUP *group, BN_GFP2 *r,
	const EC_POINT *P1, const EC_POINT *Q1,
	const EC_POINT *P2, const EC_POINT *Q2,
	BN_CTX *bn_ctx)
{
	return 0;
}

