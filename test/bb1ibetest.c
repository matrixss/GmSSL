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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bb1ibe.h>

int main(int argc, char **argv)
{
	int ret = -1;
	BB1PublicParameters *mpk = NULL;
	BB1MasterSecret *msk = NULL;
	BB1PrivateKeyBlock *sk = NULL;
	const char *id = "alice@gmssl.org";
	unsigned char mbuf[] = "hello world";
	unsigned char cbuf[2048];
	unsigned char pbuf[2048];
	size_t mlen, clen, plen;

	if (!BB1IBE_setup_by_pairing_name(NID_sm9s256t1, EVP_sha256(), &mpk, &msk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (!(sk = BB1IBE_extract_private_key(mpk, msk, id, strlen(id)))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	mlen = sizeof(mbuf);
	clen = sizeof(cbuf);
	if (!BB1IBE_encrypt(mpk, mbuf, mlen, cbuf, &clen, id, strlen(id))) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	plen = sizeof(pbuf);
	if (!BB1_decrypt(mpk, cbuf, clen, pbuf, &plen, sk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (plen != mlen || memcmp(pbuf, mbuf, mlen) != 0) {
		fprintf(stderr, "decrypt failed\n");
		goto end;
	}
	printf("BB1-IBE encryption passed\n");

	ret = 0;
end:
	BB1PublicParameters_free(mpk);
	BB1MasterSecret_free(msk);
	BB1PrivateKeyBlock_free(sk);
	return ret;
}

