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


BN_GFP2 *BN_GFP2_new(void)
{
	BN_GFP2 *ret = OPENSSL_malloc(sizeof(BN_GFP2));
	ret->a0 = BN_new();
	ret->a1 = BN_new();
	return ret;
}

void BN_GFP2_free(BN_GFP2 *a)
{
	BN_free(a->a0);
	BN_free(a->a1);
	OPENSSL_free(a);
}

int BN_GFP2_copy(BN_GFP2 *r, const BN_GFP2 *a)
{
	BN_copy(r->a0, a->a0);
	BN_copy(r->a1, a->a1);
	return 1;
}

int BN_GFP2_zero(BN_GFP2 *a)
{
	BN_zero(a->a0);
	BN_zero(a->a1);
	return 1;
}

int BN_GFP2_is_zero(const BN_GFP2 *a)
{
	return (BN_is_zero(a->a0) && BN_is_zero(a->a1));
}

int BN_GFP2_equ(const BN_GFP2 *a, const BN_GFP2 *b)
{
	return ((BN_cmp(a->a0, b->b0) == 0) && (BN_cmp(a->a1, b->a1) == 0));
}

int BN_GF2P_add(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx)
{
	BN_mod_add(r->a0, a->a0, b->a0, p, ctx);
	BN_mod_add(r->a1, a->a1, b->a1, p, ctx);
	return 1;
}

int BN_GFP2_sub(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx)
{
	BN_mod_sub(r->a0, a->a0, b->a0, p, ctx);
	BN_mod_sub(r->a1, a->a1, b->a1, p, ctx);
	return 1;
}

int BN_GFP2_mul(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *t = BN_new();
	BN_mod_mul(r->a0, a->a0, b->a0, p, ctx);
	BN_mod_mul(t,     a->a1, b->a1, p, ctx);
	BN_mod_sub(r->a0, r->a0, t,     p, ctx);
	BN_mod_mul(r->a1, a->a0, b->a1, p, ctx);
	BN_mod_mul(t,     a->a1, b->a0, p, ctx);
	BN_mod_add(r->a1, r->a1, t,     p, ctx);
	BN_free(t);
	return 1;
}

int BN_GFP2_sqr(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *p, BN_CTX *ctx)
{
	return BN_GFP2_mul(r, a, a, p, ctx);
}

int BN_GFP2_inv(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *p, BN_CTX *ctx)
{
	BIGNUM *t = BN_new();
	BN_mod_sqr(r->a0, a->a0, p, ctx);
	BN_mod_sqr(r->a1, a->a1, p, ctx);
	BN_mod_sqr(t, r->a0, r->a1, p, ctx);
	BN_mod_inverse(t, t, p, ctx);
	BN_mod_mul(r->a0, a->a0, t, p, ctx);
	BN_mod_mul(r->a1, a->a1, t, p, ctx);
	BN_sub(r->a1, p, r->a1);
	BN_free(t);
	return 1;
}

int BN_GFP2_div(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx)
{
	BN_GFP2_inv(r, b, p, ctx);
	BN_GFP2_mul(r, a, r, p, ctx);
	return 1;
}

int BN_GFP2_set_bn(BN_GFP2 *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
	PAIRINGerr(PAIRING_F_BN_GFP2_SET_BN, PAIRING_R_NOT_IMPLEMENTED);
	return 0;
}

int BN_GFP2_add_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	PAIRINGerr(PAIRING_F_BN_GFP2_ADD_BN, PAIRING_R_NOT_IMPLEMENTED);
	return 0;
}

int BN_GFP2_sub_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	PAIRINGerr(PAIRING_F_BN_GFP2_SUB_BN, PAIRING_R_NOT_IMPLEMENTED);
	return 0;
}

int BN_GFP2_mul_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	PAIRINGerr(PAIRING_F_BN_GFP2_MUL_BN, PAIRING_R_NOT_IMPLEMENTED);
	return 0;
}

int BN_GFP2_div_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b,
	const BIGNUM *p, BN_CTX *ctx)
{
	PAIRINGerr(PAIRING_F_BN_GFP2_DIV_BN, PAIRING_R_NOT_IMPLEMENTED);
	return 0;
}
