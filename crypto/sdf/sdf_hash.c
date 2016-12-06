/* crypto/gmapi/sdf_lib.c */
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
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES
 * LOSS OF USE, DATA, OR PROFITS OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/skf.h>
#include <openssl/sdf.h>
#include <openssl/rand.h>
#include <openssl/gmapi.h>
#include "gmapi_lcl.h"
#include "sdf_lcl.h"


int gmssl_SDF_HashInit(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength)
{
	int ret = SDR_UNKNOWERR;
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;
	EVP_MD_CTX *md_ctx = NULL;
	const EVP_MD *md;

	/* check arguments */
	if (!hSessionHandle) {
		GMAPIerr(GMAPI_F_SDF_HASHINIT, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (session->md_ctx) {
		GMAPIerr(GMAPI_F_SDF_HASHINIT, GMAPI_R_INVALID_OPERATION_STATE);
		return SDR_UNKNOWERR;
	}
	if (!(md = EVP_get_digestbysgd(uiAlgID))) {
		GMAPIerr(GMAPI_F_SDF_HASHINIT, GMAPI_R_INVALID_ALGOR);
		return SDR_UNKNOWERR;
	}

	/* malloc and init */
	if (!(md_ctx = EVP_MD_CTX_new())) {
		GMAPIerr(GMAPI_F_SDF_HASHINIT, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!EVP_DigestInit_ex(md_ctx, md, session->engine)) {
		GMAPIerr(GMAPI_F_SDF_HASHINIT, ERR_R_EVP_LIB);
		goto end;
	}

	session->md_ctx = md_ctx;
	ret = SDR_OK;

end:
	if (ret != SDR_OK) {
		EVP_MD_CTX_free(md_ctx);
	}
	return ret;
}

int gmssl_SDF_HashUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength)
{
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;

	/* check arguments */
	if (!hSessionHandle || !pucData) {
		GMAPIerr(GMAPI_F_SDF_HASHUPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (!session->md_ctx) {
		GMAPIerr(GMAPI_F_SDF_HASHUPDATE, GMAPI_R_INVALID_OPERATION_STATE);
		return SDR_UNKNOWERR;
	}

	/* update */
	if (!EVP_DigestUpdate(session->md_ctx, pucData, (size_t)uiDataLength)) {
		GMAPIerr(GMAPI_F_SDF_HASHUPDATE, ERR_R_EVP_LIB);
		return SDR_UNKNOWERR;
	}

	return SDR_OK;
}

int gmssl_SDF_HashFinal(void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength)
{
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;

	/* check arguments */
	if (!hSessionHandle || !pucHash || !puiHashLength) {
		GMAPIerr(GMAPI_F_SDF_HASHFINAL, ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (!session->md_ctx) {
		GMAPIerr(GMAPI_F_SDF_HASHFINAL,
			GMAPI_R_INVALID_OPERATION_STATE);
		return SDR_UNKNOWERR;
	}
	if (*puiHashLength < EVP_MD_CTX_size(session->md_ctx)) {
		GMAPIerr(GMAPI_F_SDF_HASHFINAL, GMAPI_R_BUFFER_TOO_SMALL);
		return SDR_UNKNOWERR;
	}

	/* digest final */
	if (!EVP_DigestFinal_ex(session->md_ctx, pucHash, puiHashLength)) {
		GMAPIerr(GMAPI_F_SDF_HASHFINAL, ERR_R_EVP_LIB);
		return SDR_UNKNOWERR;
	}

	/* note: only success, the md_ctx can be free-ed */
	EVP_MD_CTX_free(session->md_ctx);
	session->md_ctx = NULL;

	return SDR_OK;
}

