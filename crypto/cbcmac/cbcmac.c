/* crypto/cbcmac/cbcmac.c */
/* ====================================================================
 * Copyright (c) 2015-2016 The GmSSL Project.  All rights reserved.
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
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/cbcmac.h>

struct CBCMAC_CTX_st {
	EVP_CIPHER_CTX *cipher_ctx;
	unsigned char cbcstate[EVP_MAX_BLOCK_LENGTH];
	unsigned char workspace[EVP_MAX_BLOCK_LENGTH];
	int worklen;
};


CBCMAC_CTX *CBCMAC_CTX_new(void)
{
	CBCMAC_CTX *ret;

	if (!(ret = OPENSSL_malloc(sizeof(*ret)))) {
		return NULL;
	}
	if (!(ret->cipher_ctx = EVP_CIPHER_CTX_new())) {
		return NULL;
	}

	return ret;
}

void CBCMAC_CTX_cleanup(CBCMAC_CTX *ctx)
{
	EVP_CIPHER_CTX_free(ctx->cipher_ctx);
	OPENSSL_cleanse(ctx->cbcstate, EVP_MAX_BLOCK_LENGTH);
	OPENSSL_cleanse(ctx->workspace, EVP_MAX_BLOCK_LENGTH);
}

EVP_CIPHER_CTX *CBCMAC_CTX_get0_cipher_ctx(CBCMAC_CTX *ctx)
{
	return ctx->cipher_ctx;
}

void CBCMAC_CTX_free(CBCMAC_CTX *ctx)
{
	if (ctx) {
		CBCMAC_CTX_cleanup(ctx);
		OPENSSL_free(ctx);
	}
}

int CBCMAC_CTX_copy(CBCMAC_CTX *to, const CBCMAC_CTX *from)
{
	return 0;
}

int CBCMAC_Init(CBCMAC_CTX *ctx, const void *key, size_t keylen,
	const EVP_CIPHER *cipher, ENGINE *eng)
{
	int block_size;

	if (!EVP_EncryptInit_ex(ctx->cipher_ctx, cipher, eng, key, NULL)) {
		return 0;
	}
	if (EVP_CIPHER_CTX_mode(ctx->cipher_ctx) != EVP_CIPH_ECB_MODE) {
		return 0;
	}
	ctx->worklen = 0;
	block_size = EVP_CIPHER_CTX_block_size(ctx->cipher_ctx);
	memset(ctx->cbcstate, 0, block_size);
	return 1;
}

int CBCMAC_Update(CBCMAC_CTX *ctx, const void *data, size_t datalen)
{
	int block_size;
	int i, n, len;
	const unsigned char *in = (const unsigned char *)data;

	block_size = EVP_CIPHER_CTX_block_size(ctx->cipher_ctx);

	if (ctx->worklen) {
		n = block_size - ctx->worklen;
		if (datalen < n) {
			for (i = 0; i < datalen; i++) {
				ctx->workspace[ctx->worklen + i] = in[i];
			}
			ctx->worklen += datalen;
			return 0;
		} else {
			for (i = 0; i < n; i++) {
				ctx->workspace[ctx->worklen + i] = in[i] ^ ctx->cbcstate[i];
			}
			if (!EVP_EncryptUpdate(ctx->cipher_ctx, ctx->cbcstate, &len,
				ctx->workspace, block_size)) {
				return 0;
			}
		}

		while (n < datalen) {
			for (i = 0; i < block_size; i++) {
				ctx->workspace[i] = in[n + i] ^ ctx->cbcstate[i];
			}
			n += block_size;

			if (!EVP_EncryptUpdate(ctx->cipher_ctx, ctx->cbcstate, &len,
				ctx->workspace, block_size)) {
				return 0;
			}
		}

		ctx->worklen = datalen - n;

		for (i = 0; i < ctx->worklen; i++) {
			ctx->workspace[i] = in[n + i];
		}

	}


	return 1;
}

int CBCMAC_Final(CBCMAC_CTX *ctx, unsigned char *out, size_t *outlen)
{
	int i;
	int block_size = EVP_CIPHER_CTX_block_size(ctx->cipher_ctx);

	if (ctx->worklen) {
		for (i = ctx->worklen; i < block_size; i++) {
			ctx->workspace[i] = ctx->cbcstate[i];
		}
		if (!EVP_EncryptUpdate(ctx->cipher_ctx, out, (int *)outlen,
			ctx->workspace, block_size)) {
			return 0;
		}

	} else {
		for (i = 0; i < block_size; i++) {
			out[i] = ctx->cbcstate[i];
		}
	}

	return 1;
}

int CBCMAC_resume(CBCMAC_CTX *ctx)
{
	return 0;
}

