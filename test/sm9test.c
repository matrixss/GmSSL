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
#include <openssl/sm9.h>

int main(int argc, char **argv)
{
	int ret = -1;
	SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;
	SM9PrivateKey *sk = NULL;
	const char *id = "alice@gmssl.org";
	unsigned char mbuf[] = "hello world";
	unsigned char cbuf[2048];
	unsigned char pbuf[2048];
	unsigned char sbuf[2048];
	unsigned char dgst[EVP_MAX_MD_SIZE];
	size_t mlen, clen, plen, slen, dgstlen;

	if (!SM9_setup_by_pairing_name(NID_sm9s256t1, &mpk, &msk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(sk = SM9_extract_private_key(mpk, msk, id, strlen(id)))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	mlen = sizeof(mbuf);
	clen = sizeof(cbuf);
	if (!SM9_encrypt_with_recommended(mpk, mbuf, mlen, cbuf, &clen, id, strlen(id))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	plen = sizeof(pbuf);
	if (!SM9_decrypt_with_recommended(mpk, cbuf, clen, pbuf, &plen, sk, id, strlen(id))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (plen != mlen || memcmp(pbuf, mbuf, mlen) != 0) {
		fprintf(stderr, "decrypt failed\n");
		goto end;
	}
	printf("sm9 encryption passed\n");

	dgstlen = sizeof(dgst);
	if (EVP_Digest(mbuf, mlen, dgst, &dgstlen, EVP_sm3(), NULL)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	slen = sizeof(sbuf);
	if (!SM9_sign(mpk, dgst, dgstlen, sbuf, &slen, sk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!SM9_verify(mpk, dgst, dgstlen, sbuf, slen, id, strlen(id))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	printf("sm9 signature scheme passed!\n");

	ret = 0;
end:
	SM9PublicParameters_free(mpk);
	SM9MasterSecret_free(msk);
	SM9PrivateKey_free(sk);
	return ret;
}

