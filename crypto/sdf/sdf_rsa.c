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
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/skf.h>
#include <openssl/sdf.h>
#include <openssl/rand.h>
#include <openssl/gmapi.h>
#include "gmapi_lcl.h"
#include "sdf_lcl.h"

/* As there are two APIs for export signing key and decryption key, this
 * means that keys with different usage can be referenced by the same
 * `uiKeyIndex`, and `uiKeyIndex` is the index of a key container.
 */
int gmssl_SDF_ExportSignPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	unsigned int uiKeyUsage = 0;

	if (!hSessionHandle || !pucPublicKey) {
		GMAPIerr(GMAPI_F_SDF_EXPORTSIGNPUBLICKEY_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(pkey = sdf_load_rsa_public_key((SDF_SESSION *)hSessionHandle,
		uiKeyIndex, uiKeyUsage))) {
		GMAPIerr(GMAPI_F_SDF_EXPORTSIGNPUBLICKEY_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	if (!RSA_get_RSArefPublicKey(EVP_PKEY_get0_RSA(pkey), pucPublicKey)) {
		GMAPIerr(GMAPI_F_SDF_EXPORTSIGNPUBLICKEY_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

int gmssl_SDF_ExportEncPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	unsigned int uiKeyUsage = 1; //FIXME

	if (!hSessionHandle || !pucPublicKey) {
		GMAPIerr(GMAPI_F_SDF_EXPORTENCPUBLICKEY_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(pkey = sdf_load_rsa_public_key((SDF_SESSION *)hSessionHandle,
		uiKeyIndex, uiKeyUsage))) {
		GMAPIerr(GMAPI_F_SDF_EXPORTENCPUBLICKEY_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	if (!RSA_get_RSArefPublicKey(EVP_PKEY_get0_RSA(pkey), pucPublicKey)) {
		GMAPIerr(GMAPI_F_SDF_EXPORTENCPUBLICKEY_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

int gmssl_SDF_GenerateKeyPair_RSA(
	void *hSessionHandle, /* not used */
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey)
{
	int ret = 0;
	RSA *rsa = NULL;

	if (!hSessionHandle || !pucPublicKey || !pucPrivateKey) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(rsa = RSA_new())) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_RSA,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!RSA_generate_key_ex(rsa, uiKeyBits, NULL, NULL)) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_RSA, ERR_R_RSA_LIB);
		goto end;
	}

	if (!RSA_get_RSArefPublicKey(rsa, pucPublicKey)) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}
	if (!RSA_get_RSArefPrivateKey(rsa, pucPrivateKey)) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = SDR_OK;

end:
	RSA_free(rsa);
	return ret;
}

/* generate session key and encrypt with internal public key */
int gmssl_SDF_GenerateKeyWithIPK_RSA(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits, /* generate key length */
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	int ret = 0;
	SDF_KEY *hkey = NULL;
	unsigned int uiKeyUsage = 1; /* FIXME: encrypt */

	if (!hSessionHandle || !pucKey || !puiKeyLength || !phKeyHandle) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHIPK_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (uiKeyBits <= 0 || uiKeyBits % 8 || uiKeyBits > EVP_MAX_KEY_LENGTH) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHIPK_RSA,
			GMAPI_R_INVALID_KEY_LENGTH);
		return 0;
	}

	if (!(hkey = OPENSSL_zalloc(sizeof(*hkey)))) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHIPK_RSA,
			ERR_R_MALLOC_FAILURE);
		return 0;
	}

	if ((ret = SDF_InternalPublicKeyOperation_RSA(
		hSessionHandle,
		uiIPKIndex,
		uiKeyUsage,
		hkey->key,
		hkey->keylen,
		pucKey,
		puiKeyLength)) != SDR_OK) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHIPK_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	*phKeyHandle = hkey;
	hkey = NULL;
	ret = SDR_OK;

end:
	OPENSSL_clear_free(hkey, sizeof(*hkey));
	return ret;
}

int gmssl_SDF_GenerateKeyWithEPK_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	int ret = 0;
	SDF_KEY *key = NULL;

	if (!hSessionHandle || !pucPublicKey || !pucKey || !puiKeyLength ||
		!phKeyHandle) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHEPK_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (uiKeyBits <= 0 || uiKeyBits % 8 || uiKeyBits >
		EVP_MAX_KEY_LENGTH) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHEPK_RSA,
			GMAPI_R_INVALID_KEY_LENGTH);
		return 0;
	}

	if (!(key = OPENSSL_zalloc(sizeof(*key)))) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHEPK_RSA,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	if ((ret = SDF_ExternalPublicKeyOperation_RSA(
		hSessionHandle,
		pucPublicKey,
		key->key,
		key->keylen,
		pucKey,
		puiKeyLength)) != SDR_OK) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHEPK_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	*phKeyHandle = key;
	key = NULL;
	ret = SDR_OK;

end:
	OPENSSL_clear_free(key, sizeof(*key));
	return ret;
}

/* Import session key `pucKey` encrypted by the internal public key indexed
 * by `uiISKIndex`. As there are no session key in device, we need to
 * decrypt the `pucKey` with the internal key `uiISKIndex`.
 */
int gmssl_SDF_ImportKeyWithISK_RSA(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	int ret = 0;
	SDF_KEY *key = NULL;
	unsigned int uiKeyUsage = 1; // FIXME: encrypt

	if (!hSessionHandle || !pucKey || !phKeyHandle) {
		GMAPIerr(GMAPI_F_SDF_IMPORTKEYWITHISK_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(key = OPENSSL_zalloc(sizeof(*key)))) {
		GMAPIerr(GMAPI_F_SDF_IMPORTKEYWITHISK_RSA,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}

	key->keylen = EVP_MAX_KEY_LENGTH;
	if ((ret = SDF_InternalPrivateKeyOperation_RSA(
		hSessionHandle,
		uiISKIndex,
		uiKeyUsage,
		pucKey,
		uiKeyLength,
		key->key,
		&key->keylen)) != SDR_OK) {
		GMAPIerr(GMAPI_F_SDF_IMPORTKEYWITHISK_RSA, ERR_R_GMAPI_LIB);
		goto end;
	}

	*phKeyHandle = key;
	key = NULL;
	ret = SDR_OK;

end:
	OPENSSL_clear_free(key, sizeof(*key));
	return ret;
}

/*
 * convert the `pucDEInput` encrypted by internal RSA public key
 * `uiKeyIndex` to `pucDEOutput` encrypted by the external RSA public key
 * `pucPublicKey`
 */
int gmssl_SDF_ExchangeDigitEnvelopeBaseOnRSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDEInput,
	unsigned int uiDELength,
	unsigned char *pucDEOutput,
	unsigned int *puiDELength)
{
	return 0;
}

int gmssl_SDF_ExternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = 0;
	RSA *rsa = NULL;
	int outlen;

	if (!hSessionHandle || !pucPublicKey || !pucDataInput ||
		!pucDataOutput || !puiOutputLength) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(rsa = RSA_new_from_RSArefPublicKey(pucPublicKey))) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	if ((outlen = RSA_public_encrypt((int)uiInputLength, pucDataInput,
		pucDataOutput, rsa, RSA_NO_PADDING)) < 0) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_RSA_LIB);
		goto end;
	}

	*puiOutputLength = (unsigned int)outlen;
	ret = SDR_OK;

end:
	RSA_free(rsa);
	return ret;
}

int gmssl_SDF_ExternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPrivateKey *pucPrivateKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = 0;
	RSA *rsa = NULL;
	int outlen;

	if (!hSessionHandle || !pucPrivateKey || !pucDataInput ||
		!pucDataOutput || !puiOutputLength) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(rsa = RSA_new_from_RSArefPrivateKey(pucPrivateKey))) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	if ((outlen = RSA_private_decrypt((int)uiInputLength, pucDataInput,
		pucDataOutput, rsa, RSA_NO_PADDING)) < 0) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_RSA_LIB);
		goto end;
	}

	*puiOutputLength = (unsigned int)outlen;
	ret = SDR_OK;

end:
	RSA_free(rsa);
	return ret;
}


int gmssl_SDF_InternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned int uiKeyUsage, /* determine encrypt or verify */
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	int outlen;

	if (!hSessionHandle || !pucDataInput || !pucDataOutput ||
		!puiOutputLength) {
		GMAPIerr(GMAPI_F_SDF_INTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(pkey = sdf_load_rsa_public_key((SDF_SESSION *)hSessionHandle,
		uiKeyIndex, uiKeyUsage))) {
		GMAPIerr(GMAPI_F_SDF_INTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	if ((outlen = RSA_public_encrypt((int)uiInputLength, pucDataInput,
		pucDataOutput, EVP_PKEY_get0_RSA(pkey), RSA_NO_PADDING)) < 0) {
		GMAPIerr(GMAPI_F_SDF_INTERNALPUBLICKEYOPERATION_RSA,
			ERR_R_RSA_LIB);
		goto end;
	}

	*puiOutputLength = (unsigned int)outlen;
	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

int gmssl_SDF_InternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned int uiKeyUsage,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	int outlen;

	if (!hSessionHandle || !pucDataInput || !pucDataOutput ||
		!puiOutputLength) {
		GMAPIerr(GMAPI_F_SDF_INTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (!(pkey = sdf_load_rsa_private_key((SDF_SESSION *)hSessionHandle,
		uiKeyIndex, uiKeyUsage))) {
		GMAPIerr(GMAPI_F_SDF_INTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	if ((outlen = RSA_private_decrypt(uiInputLength, pucDataInput,
		pucDataOutput, EVP_PKEY_get0_RSA(pkey), RSA_NO_PADDING)) < 0) {
		GMAPIerr(GMAPI_F_SDF_INTERNALPRIVATEKEYOPERATION_RSA,
			ERR_R_RSA_LIB);
		goto end;
	}

	*puiOutputLength = (unsigned int)outlen;
	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

