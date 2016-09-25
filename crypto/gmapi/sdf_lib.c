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
#include <openssl/gmapi.h>
#include "gmapi_lcl.h"

#ifndef NO_GMSSL


int SDF_OpenDevice(
	void **phDeviceHandle)
{
	return SDR_OK;
}

int SDF_CloseDevice(
	void *hDeviceHandle)
{
	return SDR_OK;
}

int SDF_OpenSession(
	void *hDeviceHandle,
	void **phSessionHandle)
{
	return SDR_OK;
}

int SDF_CloseSession(
	void *hSessionHandle)
{
	return SDR_OK;
}

int SDF_GetDeviceInfo(
	void *hSessionHandle,
	DEVICEINFO *pstDeviceInfo)
{
	return SDR_OK;
}

int SDF_GenerateRandom(
	void *hSessionHandle,
	unsigned int uiLength,
	unsigned char *pucRandom)
{
	RAND_bytes(pucRandom, uiLength);
	return SDR_OK;
}

int SDF_GetPrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucPassword,
	unsigned int uiPwdLength)
{
	return SDR_OK;
}

int SDF_ReleasePrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex)
{
	return SDR_OK;
}

// almost same to SKF
int SDF_GenerateKeyPair_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey)
{
	return 0;
}

// what is a key handle?
// it is a pointer to the key buffer
// what is the ciphertext format?

typedef struct {
	unsigned char *data;
	size_t datalen;
} SDF_KeyHandle;

int SDF_GenerateKeyWithEPK_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	// generate random symm key
	// set key handle
	// encrypt key with RSA
	return 0;
}

int SDF_ImportKey(
	void *hSessionHandle,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	return 0;
}

int SDF_DestroyKey(
	void *hSessionHandle,
	void *hKeyHandle)
{
	return 0;
}

int SDF_GenerateKeyPair_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int  uiKeyBits,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey)
{
	return 0;
}

int SDF_ExternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	return 0;
}

int SDF_ExternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPrivateKey *pucPrivateKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	return 0;
}

int SDF_ExternalSign_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPrivateKey *pucPrivateKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	return 0;
}

int SDF_ExternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	ECCSignature *pucSignature)
{
	return 0;
}

int SDF_ExternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	return 0;
}

int SDF_ExternalDecrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPrivateKey *pucPrivateKey,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	return 0;
}

int SDF_Encrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength)
{
	return 0;
}

int SDF_Decrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	return 0;
}

int SDF_CalculateMAC(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucMAC,
	unsigned int *puiMACLength)
{
	return 0;
}

int SDF_HashInit(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength)
{
	return 0;
}

int SDF_HashUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength)
{
	return 0;
}

int SDF_HashFinal(void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength)
{
	return 0;
}

int SDF_HashInit_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned char *pucParamID)
{
	return 0;
}
#endif
