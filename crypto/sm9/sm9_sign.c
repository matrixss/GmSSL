/* crypto/sm9/sm9_sign.c */
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


SM9Signature *SM9_do_sign(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	SM9PrivateKey *sk)
{
	SM9err(SM9_F_SM9_DO_SIGN, SM9_R_NOT_IMPLEMENTED);
	return NULL;
}

int SM9_do_verify(SM9PublicParameters *mpk,
	const unsigned char *dgst, size_t dgstlen,
	const SM9Signature *sig, const char *id, size_t idlen)
{
	SM9err(SM9_F_SM9_DO_VERIFY, SM9_R_NOT_IMPLEMENTED);
	return 0;
}

int SM9_sign(SM9PublicParameters *mpk, const unsigned char *dgst,
	size_t dgstlen, unsigned char *sig, size_t *siglen,
	SM9PrivateKey *sk)
{
	SM9Signature *s;

	RAND_seed(dgst, dgstlen);

	if (!(s = SM9_do_sign(mpk, dgst, dgstlen, sk))) {
		*siglen = 0;
		return 0;
	}

	*siglen = i2d_SM9Signature(s, &sig);
	SM9Signature_free(s);

	return 1;
}

int SM9_verify(SM9PublicParameters *mpk, const unsigned char *dgst,
	size_t dgstlen, const unsigned char *sig, size_t siglen,
	const char *id, size_t idlen)
{
	SM9Signature *s;
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	int derlen = -1;
	int ret = -1;

	if (!(s = SM9Signature_new())) {
		SM9err(SM9_F_SM9_VERIFY, ERR_R_MALLOC_FAILURE);
		return -1;
	}
	if (!d2i_SM9Signature(&s, &p, siglen)) {
		goto end;
	}
	derlen = i2d_SM9Signature(s, &der);
	if (derlen != siglen || memcmp(sig, der, derlen)) {
		goto end;
	}

	ret = SM9_do_verify(mpk, dgst, dgstlen, s, id, idlen);

end:
	if (derlen > 0) {
		OPENSSL_cleanse(der, derlen);
		OPENSSL_free(der);
	}

	SM9Signature_free(s);
	return ret;
}

