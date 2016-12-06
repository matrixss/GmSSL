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
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/gmapi.h>
#include <openssl/sdf.h>
#include <openssl/sgd.h>
#include <openssl/skf.h>
#include "gmapi_lcl.h"
#include "sdf_lcl.h"


int gmssl_SDF_GenerateKeyPair_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int  uiKeyBits,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey)
{
	int ret = SDR_UNKNOWERR;
	EC_KEY *ec_key = NULL;

	/* check arguments */
	if (!hSessionHandle || !pucPublicKey || !pucPrivateKey) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (uiAlgID != SGD_SM2 && uiAlgID != SGD_SM2_1 &&
		uiAlgID != SGD_SM2_2 && uiAlgID != SGD_SM2_3) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_ECC,
			GMAPI_R_INVALID_ALGOR);
		return SDR_UNKNOWERR;
	}
	if (uiKeyBits != 256) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_ECC,
			GMAPI_R_INVALID_KEY_LENGTH);
		return SDR_UNKNOWERR;
	}

	/* generate */
	if(!(ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1))) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_ECC, ERR_R_EC_LIB);
		goto end;
	}

	/* convert */
	if (!EC_KEY_get_ECCrefPublicKey(ec_key, pucPublicKey)) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_ECC,
			GMAPI_R_GET_PUBLIC_KEY_FAILED);
		goto end;
	}
	if (!EC_KEY_get_ECCrefPrivateKey(ec_key, pucPrivateKey)) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYPAIR_ECC,
			GMAPI_R_GET_PRIVATE_KEY_FAILED);
		goto end;
	}

	ret = SAR_OK;
end:
	EC_KEY_free(ec_key);
	return ret;
}

int gmssl_SDF_ExportSignPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	int ret = SDR_UNKNOWERR;
	EVP_PKEY *pkey = NULL;
	unsigned int uiKeyUsage = SGD_SM2_1;

	/* check arguments */
	if (!hSessionHandle || !pucPublicKey) {
		GMAPIerr(GMAPI_F_SDF_EXPORTSIGNPUBLICKEY_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}

	/* load key */
	if (!(pkey = sdf_load_ec_public_key(hSessionHandle,
		uiKeyIndex, uiKeyUsage))) {
		GMAPIerr(GMAPI_F_SDF_EXPORTSIGNPUBLICKEY_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	/* set return value */
	if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(pkey),
		pucPublicKey)) {
		GMAPIerr(GMAPI_F_SDF_EXPORTSIGNPUBLICKEY_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}
	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

int gmssl_SDF_ExportEncPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	int ret = SDR_UNKNOWERR;
	EVP_PKEY *pkey = NULL;
	unsigned int uiKeyUsage = 1;

	/* check arguments */
	if (!hSessionHandle || !pucPublicKey) {
		GMAPIerr(GMAPI_F_SDF_EXPORTENCPUBLICKEY_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}

	/* load key */
	if (!(pkey = sdf_load_ec_public_key(hSessionHandle,
		uiKeyIndex, uiKeyUsage))) {
		GMAPIerr(GMAPI_F_SDF_EXPORTENCPUBLICKEY_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	/* set return value */
	if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(pkey),
		pucPublicKey)) {
		GMAPIerr(GMAPI_F_SDF_EXPORTENCPUBLICKEY_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}
	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

int gmssl_SDF_GenerateAgreementDataWithECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	void **phAgreementHandle)
{
	return 0;
}

int gmssl_SDF_GenerateKeyWithECC(
	void *hSessionHandle,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void *hAgreementHandle,
	void **phKeyHandle)
{
	return 0;
}

int gmssl_SDF_GenerateAgreementDataAndKeyWithECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void **phKeyHandle)
{
	return 0;
}

/* generate a session key and encrypt it with internal public key
 * we can first random a key,
 * export the public key,
 * and then use the SDF_GenerateKeyWithEPK_ECC to encrypt the key
 * the output key handle is only a pointer to the key buffer.
 */
int gmssl_SDF_GenerateKeyWithIPK_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits, /* output session key length */
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;
	SDF_KEY *key = NULL;
	unsigned int uiAlgID = SGD_SM2_3;

	/* check arguments */
	if (!hSessionHandle || !pucKey || !phKeyHandle) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHIPK_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (uiKeyBits <= 0 || uiKeyBits > EVP_MAX_KEY_LENGTH * 8 ||
		uiKeyBits % 8) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHIPK_ECC,
			GMAPI_R_INVALID_KEY_LENGTH);
		return SDR_UNKNOWERR;
	}

	/* random key */
	if (!(key = OPENSSL_zalloc(sizeof(*key)))) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHIPK_ECC,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	key->keylen = uiKeyBits/8;
	if ((ret = SDF_GenerateRandom(hSessionHandle, key->keylen,
		key->key)) != SDR_OK) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHIPK_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	/* encrypt key with external ec public key */
	if ((ret = SDF_InternalEncrypt_ECC(
		hSessionHandle,
		uiIPKIndex,
		uiAlgID,
		key->key,
		key->keylen,
		pucKey)) != SDR_OK) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHIPK_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	/* set return value */
	*phKeyHandle = key;
	key = NULL;
	ret = SDR_OK;

end:
	OPENSSL_clear_free(key, sizeof(*key));
	return ret;
}

int gmssl_SDF_GenerateKeyWithEPK_ECC(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID, /* must be SGD_SM2_3 */
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;
	SDF_KEY *key = NULL;

	/* check arguments */
	if (!hSessionHandle || !pucPublicKey || !pucKey || !phKeyHandle) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHEPK_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (uiKeyBits <= 0 || uiKeyBits >= EVP_MAX_KEY_LENGTH * 8 ||
		uiKeyBits % 8) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHEPK_ECC,
			GMAPI_R_INVALID_KEY_LENGTH);
		return SDR_UNKNOWERR;
	}
	if (uiAlgID != SGD_SM2_3) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHEPK_ECC,
			GMAPI_R_INVALID_ALGOR);
		return SDR_UNKNOWERR;
	}

	/* random key */
	if (!(key = OPENSSL_zalloc(sizeof(*key)))) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHEPK_ECC,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	key->keylen = uiKeyBits/8;
	if ((ret = SDF_GenerateRandom(hSessionHandle, key->keylen,
		key->key)) != SDR_OK) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHEPK_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	/* encrypt key with external ec public key */
	if ((ret = SDF_ExternalEncrypt_ECC(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		key->key,
		key->keylen,
		pucKey)) != SDR_OK) {
		GMAPIerr(GMAPI_F_SDF_GENERATEKEYWITHEPK_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	/* set return value */
	*phKeyHandle = key;
	key = NULL;
	ret = SDR_OK;

end:
	OPENSSL_clear_free(key, sizeof(*key));
	return ret;
}

/* import session key
 * use the engine to decrypt the ECCipher
 */
int gmssl_SDF_ImportKeyWithISK_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	int ret = SDR_UNKNOWERR;
	SDF_KEY *key = NULL;
	unsigned int uiAlgID = SGD_SM2_3;

	/* check arguments */
	if (!hSessionHandle || !pucKey || !phKeyHandle) {
		GMAPIerr(GMAPI_F_SDF_IMPORTKEYWITHISK_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}

	/* prepare key */
	if (!(key = OPENSSL_zalloc(sizeof(*key)))) {
		GMAPIerr(GMAPI_F_SDF_IMPORTKEYWITHISK_ECC,
			ERR_R_MALLOC_FAILURE);
		goto end;
	}
	key->keylen = EVP_MAX_KEY_LENGTH;

	/* decrypt with internal ec private key */
	if ((ret = SDF_InternalDecrypt_ECC(
		hSessionHandle,
		uiISKIndex,
		uiAlgID,
		pucKey,
		key->key,
		&key->keylen)) != SDR_OK) {
		GMAPIerr(GMAPI_F_SDF_IMPORTKEYWITHISK_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}

	/* set return value */
	*phKeyHandle = key;
	key = NULL;
	ret = SDR_OK;

end:
	OPENSSL_clear_free(key, sizeof(*key));
	return ret;
}

int gmssl_SDF_ExchangeDigitEnvelopeBaseOnECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucEncDataIn,
	ECCCipher *pucEncDataOut)
{
	return 0;
}

/*
 * Implementation of SM2 signing
 *
 * Although the digest and signing operations should be the wrapping of the EVP
 * API, it will be simpler when using the native API of the `sm2` module.
 * Another consideration is that the usage of SM2 EVP might be changed, and the
 * operations might also be different from the GM standards, like signing the
 * H(Z||H(M)) instead of signing H(Z||M). So in the GMAPI we use the SM2 API
 * directly.
 */

int gmssl_SDF_ExternalSign_ECC(
	void *hSessionHandle, /* no use so not checked */
	unsigned int uiAlgID, /* must be SGD_SM2_1 */
	ECCrefPrivateKey *pucPrivateKey,
	unsigned char *pucData, /* digest */
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	int ret = SDR_UNKNOWERR;
	EC_KEY *ec_key = NULL;
	ECDSA_SIG *sig = NULL;

	/* check arguments */
	if (!hSessionHandle || !pucData || !pucSignature) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALSIGN_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (uiAlgID != SGD_SM2_1) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALSIGN_ECC,
			GMAPI_R_INVALID_ALGOR);
		return 0;
	}
	if (uiDataLength > INT_MAX) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALSIGN_ECC,
			GMAPI_R_INVALID_INPUT_LENGTH);
		return 0;
	}

	/* load ec private key */
	if (!(ec_key = EC_KEY_new_from_ECCrefPrivateKey(pucPrivateKey))) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALSIGN_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}
	if (!(sig = SM2_do_sign(pucData, uiDataLength, ec_key))) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALSIGN_ECC,
			ERR_R_EC_LIB);
		goto end;
	}

	/* set return value */
	if (!ECDSA_SIG_get_ECCSignature(sig, pucSignature)) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALSIGN_ECC,
			ERR_R_GMAPI_LIB);
		goto end;
	}
	ret = SDR_OK;

end:
	EC_KEY_free(ec_key);
	ECDSA_SIG_free(sig);
	return ret;
}

int gmssl_SDF_ExternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	ECCSignature *pucSignature)
{
	int ret = SDR_UNKNOWERR;
	EC_KEY *ec_key = NULL;
	ECDSA_SIG *sig = NULL;

	/* check arguments */
	if (!hSessionHandle || !pucPublicKey || !pucDataInput ||
		!pucSignature) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALVERIFY_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (uiAlgID != SGD_SM2_1) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALVERIFY_ECC,
			GMAPI_R_INVALID_ALGOR);
		return SDR_UNKNOWERR;
	}
	if (uiInputLength != SM3_DIGEST_LENGTH) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALVERIFY_ECC,
			GMAPI_R_INVALID_INPUT_LENGTH);
		return SDR_UNKNOWERR;
	}

	/* parse arguments */
	if (!(ec_key = EC_KEY_new_from_ECCrefPublicKey(pucPublicKey))) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALVERIFY_ECC,
			GMAPI_R_INVALID_EC_PUBLIC_KEY);
		goto end;
	}
	if (!(sig = SM2_do_sign(pucDataInput, uiInputLength, ec_key))) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALVERIFY_ECC, ERR_R_EC_LIB);
		goto end;
	}
	if (!ECDSA_SIG_get_ECCSignature(sig, pucSignature)) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALVERIFY_ECC, ERR_R_GMAPI_LIB);
		goto end;
	}

	/* set return value */
	ret = SDR_OK;

end:
	EC_KEY_free(ec_key);
	ECDSA_SIG_free(sig);
	return ret;
}

int gmssl_SDF_ExternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID, /* SGD_SM2_3 */
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	int ret = SDR_UNKNOWERR;
	EC_KEY *ec_key = NULL;
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	SM2_ENC_PARAMS params;

	/* check arguments */
	if (!hSessionHandle || !pucPublicKey || !pucData || !pucEncData) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALENCRYPT_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (uiAlgID != SGD_SM2_3) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALENCRYPT_ECC,
			GMAPI_R_INVALID_ALGOR);
		return 0;
	}
	if (uiDataLength > ECCref_MAX_CIPHER_LEN) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALENCRYPT_ECC,
			GMAPI_R_INVALID_INPUT_LENGTH);
		return 0;
	}

	/* parse public key */
	if (!(ec_key = EC_KEY_new_from_ECCrefPublicKey(pucPublicKey))) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALENCRYPT_ECC, ERR_R_GMAPI_LIB);
		goto end;
	}

	/* encrypt */
	(void)SM2_ENC_PARAMS_init_with_recommended(&params);
	if (!(cv = SM2_do_encrypt(&params, pucData, (size_t)uiDataLength,
		ec_key))) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALENCRYPT_ECC, ERR_R_EC_LIB);
		goto end;
	}
	/* encode ciphertext */
	if (!SM2_CIPHERTEXT_VALUE_get_ECCCipher(cv, pucEncData)) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALENCRYPT_ECC, ERR_R_EC_LIB);
		goto end;
	}

	ret = SDR_OK;

end:
	EC_KEY_free(ec_key);
	SM2_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

int gmssl_SDF_ExternalDecrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPrivateKey *pucPrivateKey,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	int ret = SDR_UNKNOWERR;
	EC_KEY *ec_key = NULL;
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	SM2_ENC_PARAMS params;
	size_t siz;

	/* check arguments */
	if (!hSessionHandle || !pucPrivateKey || !pucEncData ||
		!pucData || !puiDataLength) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALDECRYPT_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (*puiDataLength < ECCref_MAX_CIPHER_LEN) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALDECRYPT_ECC,
			GMAPI_R_BUFFER_TOO_SMALL);
		return SDR_UNKNOWERR;
	}

	/* parse arguments */
	if (!(ec_key = EC_KEY_new_from_ECCrefPrivateKey(pucPrivateKey))) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALDECRYPT_ECC,
			GMAPI_R_INVALID_EC_PRIVATE_KEY);
		goto end;
	}
	if (!(cv = SM2_CIPHERTEXT_VALUE_new_from_ECCCipher(pucEncData))) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALDECRYPT_ECC,
			GMAPI_R_INVALID_EC_CIPHERTEXT);
		goto end;
	}

	/* decrypt */
	(void)SM2_ENC_PARAMS_init_with_recommended(&params);
	siz = (size_t)*puiDataLength;
	if (!SM2_do_decrypt(&params, cv, pucData, &siz, ec_key)) {
		GMAPIerr(GMAPI_F_SDF_EXTERNALDECRYPT_ECC, ERR_R_EC_LIB);
	}

	/* set return value */
	*puiDataLength = (unsigned int)siz;
	ret = SDR_OK;

end:
	EC_KEY_free(ec_key);
	SM2_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

/* internal private key operation will use ENGINE */
int gmssl_SDF_InternalSign_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	int ret = 0;
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	unsigned char buf[256/4 + 32];
	size_t siz;

	/* check arguments */
	if (!hSessionHandle || !pucData || !pucSignature) {
		GMAPIerr(GMAPI_F_SDF_INTERNALSIGN_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (uiDataLength > SM3_DIGEST_LENGTH) {
		GMAPIerr(GMAPI_F_SDF_INTERNALSIGN_ECC,
			GMAPI_R_INVALID_INPUT_LENGTH);
		return SDR_UNKNOWERR;
	}

	/* parse arguments */
	if (!(pkey = sdf_load_ec_private_key(hSessionHandle, uiISKIndex,
		SGD_PK_SIGN))) {
		GMAPIerr(GMAPI_F_SDF_INTERNALSIGN_ECC,
			GMAPI_R_INVALID_KEY_HANDLE);
		goto end;
	}

	/* sign
	 * use the EVP API instead of the native SM2 API to use ENGINE
	 */
	if (!(ctx = EVP_PKEY_CTX_new(pkey, session->engine))) {
		GMAPIerr(GMAPI_F_SDF_INTERNALSIGN_ECC, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_PKEY_sign_init(ctx)) {
		GMAPIerr(GMAPI_F_SDF_INTERNALSIGN_ECC, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme)) {
		GMAPIerr(GMAPI_F_SDF_INTERNALSIGN_ECC, ERR_R_EVP_LIB);
		goto end;
	}
	siz = sizeof(buf);
	if (!EVP_PKEY_sign(ctx, buf, &siz, pucData, (size_t)uiDataLength)) {
		GMAPIerr(GMAPI_F_SDF_INTERNALSIGN_ECC, ERR_R_EVP_LIB);
		goto end;
	}

	/* convert signature buf to ECCSignature */
	if (!sdf_decode_ec_signature(pucSignature, buf, siz)) {
		GMAPIerr(GMAPI_F_SDF_INTERNALSIGN_ECC, ERR_R_GMAPI_LIB);
		goto end;
	}

	/* set return value */
	ret = SDR_OK;

end:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return ret;
}

int gmssl_SDF_InternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	int ret = SDR_UNKNOWERR;
	SDF_SESSION *session = (SDF_SESSION *)hSessionHandle;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char buf[521/4 + 32];
	size_t siz;

	/* check arguments */
	if (!hSessionHandle || !pucData || !pucSignature) {
		GMAPIerr(GMAPI_F_SDF_INTERNALVERIFY_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}
	if (uiDataLength != SM3_DIGEST_LENGTH) {
		GMAPIerr(GMAPI_F_SDF_INTERNALVERIFY_ECC,
			GMAPI_R_INVALID_INPUT_LENGTH);
		return SDR_UNKNOWERR;
	}

	/* parse arguments */
	if (!(pkey = sdf_load_ec_public_key(hSessionHandle, uiIPKIndex,
		SGD_PK_SIGN))) {
		GMAPIerr(GMAPI_F_SDF_INTERNALVERIFY_ECC, ERR_R_GMAPI_LIB);
		goto end;
	}
	siz = sizeof(buf);
	if (!sdf_encode_ec_signature(pucSignature, buf, &siz)) {
		GMAPIerr(GMAPI_F_SDF_INTERNALVERIFY_ECC, ERR_R_GMAPI_LIB);
		goto end;
	}

	/* verify with EVP API and ENGINE */
	if (!(ctx = EVP_PKEY_CTX_new(pkey, session->engine))) {
		GMAPIerr(GMAPI_F_SDF_INTERNALVERIFY_ECC, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_PKEY_verify_init(ctx)) {
		GMAPIerr(GMAPI_F_SDF_INTERNALVERIFY_ECC, ERR_R_EVP_LIB);
		goto end;
	}
	if (!EVP_PKEY_CTX_set_ec_scheme(ctx, NID_sm_scheme)) {
		GMAPIerr(GMAPI_F_SDF_INTERNALVERIFY_ECC, ERR_R_EVP_LIB);
		goto end;
	}
	if (1 != EVP_PKEY_verify(ctx, buf, siz, pucData,
		(size_t)uiDataLength)) {
		GMAPIerr(GMAPI_F_SDF_INTERNALVERIFY_ECC, ERR_R_EVP_LIB);
		goto end;
	}

	ret = SDR_OK;

end:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return ret;
}

int gmssl_SDF_InternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiAlgID,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	SM2_ENC_PARAMS params;

	/* check arguments */
	if (!hSessionHandle || !pucData || !pucEncData) {
		GMAPIerr(GMAPI_F_SDF_INTERNALENCRYPT_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (uiDataLength > ECCref_MAX_LEN) {
		GMAPIerr(GMAPI_F_SDF_INTERNALENCRYPT_ECC,
			GMAPI_R_INVALID_INPUT_LENGTH);
		return 0;
	}

	if (!(pkey = sdf_load_ec_public_key((SDF_SESSION *)hSessionHandle,
		uiIPKIndex, uiAlgID))) {
		GMAPIerr(GMAPI_F_SDF_INTERNALENCRYPT_ECC, ERR_R_GMAPI_LIB);
		goto end;
	}

	(void)SM2_ENC_PARAMS_init_with_recommended(&params);

	/* we need to use the EVP_PKEY interface to use ENGINE ?*/
	if (!(cv = SM2_do_encrypt(&params, pucData, (size_t)uiDataLength,
		EVP_PKEY_get0_EC_KEY(pkey)))) {
		GMAPIerr(GMAPI_F_SDF_INTERNALENCRYPT_ECC, ERR_R_EC_LIB);
		goto end;
	}

	if (!SM2_CIPHERTEXT_VALUE_get_ECCCipher(cv, pucEncData)) {
		GMAPIerr(GMAPI_F_SDF_INTERNALENCRYPT_ECC, ERR_R_EC_LIB);
		goto end;
	}

	ret = SDR_OK;

end:
	EVP_PKEY_free(pkey);
	SM2_CIPHERTEXT_VALUE_free(cv);
	return ret;
}

int gmssl_SDF_InternalDecrypt_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiAlgID,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;


	/* check arguments */
	if (!hSessionHandle || !pucEncData || !pucData || !puiDataLength) {
		GMAPIerr(GMAPI_F_SDF_INTERNALDECRYPT_ECC,
			ERR_R_PASSED_NULL_PARAMETER);
		return SDR_UNKNOWERR;
	}

	if (!(pkey = sdf_load_ec_private_key(hSessionHandle,
		uiISKIndex, uiAlgID))) {
		GMAPIerr(GMAPI_F_SDF_INTERNALDECRYPT_ECC, ERR_R_GMAPI_LIB);
		goto end;
	}




end:
	return 0;
}

