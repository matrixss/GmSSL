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
#include <stdlib.h>
#include <string.h>
#include <openssl/sgd.h>
#include <openssl/sdf.h>


int SDF_OpenDevice(
	phDeviceHandle)
{
	return sdf->OpenDevice(
		phDeviceHandle);
}

int SDF_CloseDevice(
	void *hDeviceHandle)
{
	return sdf->CloseDevice(
		hDeviceHandle);
}

int SDF_OpenSession(
	void *hDeviceHandle,
	phSessionHandle)
{
	return sdf->OpenSession(
		hDeviceHandle,
		phSessionHandle);
}

int SDF_CloseSession(
	void *hSessionHandle)
{
	return sdf->CloseSession(hSessionHandle);
}

int SDF_GetDeviceInfo(
	void *hSessionHandle,
	DEVICEINFO *pstDeviceInfo)
{
	return sdf->GetDeviceInfo(
		hSessionHandle,
		pstDeviceInfo);
}

int SDF_GenerateRandom(
	void *hSessionHandle,
	unsigned int uiLength,
	unsigned char *pucRandom)
{
	return sdf->GenerateRandom(
		hSessionHandle,
		uiLength,
		pucRandom);
}

int SDF_GetPrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucPassword,
	unsigned int uiPwdLength)
{
	return sdf->GetPrivateKeyAccessRight(
		hSessionHandle,
		uiKeyIndex,
		pucPassword,
		uiPwdLength);
}

int SDF_ReleasePrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex)
{
	return sdf->ReleasePrivateKeyAccessRight(
		hSessionHandle,
		uiKeyIndex)
}

int SDF_ExportSignPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	return sdf->ExportSignPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey);
}

int SDF_ExportEncPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	return sdf->ExportEncPublicKey_RSA(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey);
}

int SDF_GenerateKeyPair_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey)
{
	return sdf->GenerateKeyPair_RSA(
		hSessionHandle,
		uiKeyBits,
		pucPublicKey,
		pucPrivateKey);
}

int SDF_GenerateKeyWithIPK_RSA(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	phKeyHandle)
{
	return sdf->GenerateKeyWithIPK_RSA(
		hSessionHandle,
		uiIPKIndex,
		uiKeyBits,
		pucKey,
		puiKeyLength,
		phKeyHandle);
}

int SDF_GenerateKeyWithEPK_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	phKeyHandle)
{
	return sdf->GenerateKeyWithEPK_RSA(
		hSessionHandle,
		uiKeyBits,
		pucPublicKey,
		pucKey,
		puiKeyLength,
		phKeyHandle);
}

int SDF_ImportKeyWithISK_RSA(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	phKeyHandle)
{
	return sdf->ImportKeyWithISK_RSA(
		hSessionHandle,
		uiISKIndex,
		pucKey,
		uiKeyLength,
		phKeyHandle);
}

int SDF_ExchangeDigitEnvelopeBaseOnRSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDEInput,
	unsigned int uiDELength,
	unsigned char *pucDEOutput,
	unsigned int *puiDELength)
{
	return sdf->ExchangeDigitEnvelopeBaseOnRSA(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey,
		pucDEInput,
		uiDELength,
		pucDEOutput,
		puiDELength);
}

int SDF_ExportSignPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	return sdf->ExportSignPublicKey_ECC(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey);
}

int SDF_ExportEncPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	return sdf->ExportEncPublicKey_ECC(
		hSessionHandle,
		uiKeyIndex,
		pucPublicKey);
}

int SDF_GenerateKeyPair_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int  uiKeyBits,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey)
{
	return sdf->GenerateKeyPair_ECC(
		hSessionHandle,
		uiAlgID,
		uiKeyBits,
		pucPublicKey,
		pucPrivateKey);
}

int SDF_GenerateKeyWithIPK_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	return sdf->GenerateKeyWithIPK_ECC(
		hSessionHandle,
		uiIPKIndex,
		uiKeyBits,
		pucKey,
		phKeyHandle);
}

int SDF_GenerateKeyWithEPK_ECC(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucKey,
	phKeyHandle)
{
	return sdf->GenerateKeyWithEPK_ECC(
		hSessionHandle,
		uiKeyBits,
		uiAlgID,
		pucPublicKey,
		pucKey,
		phKeyHandle);
}

int SDF_ImportKeyWithISK_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	return sdf->ImportKeyWithISK_ECC(
		hSessionHandle,
		uiISKIndex,
		pucKey,
		phKeyHandle);
}

int SDF_GenerateAgreementDataWithECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	void **phAgreementHandle)
{
	return sdf->GenerateAgreementDataWithECC(
		hSessionHandle,
		uiISKIndex,
		uiKeyBits,
		pucSponsorID,
		uiSponsorIDLength,
		pucSponsorPublicKey,
		pucSponsorTmpPublicKey,
		phAgreementHandle);
}

int SDF_GenerateKeyWithECC(
	void *hSessionHandle,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void *hAgreementHandle,
	phKeyHandle)
{
	return sdf->GenerateKeyWithECC(
		hSessionHandle,
		pucResponseID,
		uiResponseIDLength,
		pucResponsePublicKey,
		pucResponseTmpPublicKey,
		hAgreementHandle,
		phKeyHandle);
}

int SDF_GenerateAgreementDataAndKeyWithECC(
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
	return sdf->GenerateAgreementDataAndKeyWithECC(
		hSessionHandle,
		uiISKIndex,
		uiKeyBits,
		pucResponseID,
		uiResponseIDLength,
		pucSponsorID,
		uiSponsorIDLength,
		pucSponsorPublicKey,
		pucSponsorTmpPublicKey,
		pucResponsePublicKey,
		pucResponseTmpPublicKey,
		phKeyHandle);
}

int SDF_ExchangeDigitEnvelopeBaseOnECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucEncDataIn,
	ECCCipher *pucEncDataOut)
{
	return sdf->ExchangeDigitEnvelopeBaseOnECC(
		hSessionHandle,
		uiKeyIndex,
		uiAlgID,
		pucPublicKey,
		pucEncDataIn,
		pucEncDataOut);
}

int SDF_GenerateKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	return sdf->GenerateKeyWithKEK(
		hSessionHandle,
		uiKeyBits,
		uiAlgID,
		uiKEKIndex,
		pucKey,
		puiKeyLength,
		phKeyHandle);
}

int SDF_ImportKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	return sdf->ImportKeyWithKEK(
		hSessionHandle,
		uiAlgID,
		uiKEKIndex,
		pucKey,
		uiKeyLength,
		phKeyHandle);
}

int SDF_DestroyKey(
	void *hSessionHandle,
	void *hKeyHandle)
{
	return sdf->DestroyKey(
		hSessionHandle,
		hKeyHandle);
}

int SDF_ExternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	return sdf->ExternalPublicKeyOperation_RSA(
		hSessionHandle,
		pucPublicKey,
		pucDataInput,
		uiInputLength,
		pucDataOutput,
		puiOutputLength);
}

int SDF_ExternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPrivateKey *pucPrivateKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	return sdf->ExternalPrivateKeyOperation_RSA(
		hSessionHandle,
		pucPrivateKey,
		pucDataInput,
		uiInputLength,
		pucDataOutput,
		puiOutputLength);
}

int SDF_InternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength)
{
	return sdf->InternalPrivateKeyOperation_RSA(
		hSessionHandle,
		uiKeyIndex,
		pucDataInput,
		uiInputLength,
		pucDataOutput,
		puiOutputLength);
}

int SDF_ExternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	ECCSignature *pucSignature)
{
	return sdf->ExternalVerify_ECC(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		pucDataInput,
		uiInputLength,
		pucSignature);
}

int SDF_InternalSign_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	return sdf->InternalSign_ECC(
		hSessionHandle,
		uiISKIndex,
		pucData,
		uiDataLength,
		pucSignature);
}

int SDF_InternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	return sdf->InternalVerify_ECC(
		hSessionHandle,
		uiIPKIndex,
		pucData,
		uiDataLength,
		pucSignature);
}

int SDF_ExternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	return sdf->ExternalEncrypt_ECC(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		pucData,
		uiDataLength,
		pucEncData);
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
	return sdf->Encrypt(
		hSessionHandle,
		hKeyHandle,
		uiAlgID,
		pucIV,
		pucData,
		uiDataLength,
		pucEncData,
		puiEncDataLength);
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
	return sdf->Decrypt(
		hSessionHandle,
		hKeyHandle,
		uiAlgID,
		pucIV,
		pucEncData,
		uiEncDataLength,
		pucData,
		puiDataLength);
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
	return sdf->CalculateMAC(
		hSessionHandle,
		hKeyHandle,
		uiAlgID,
		pucIV,
		pucData,
		uiDataLength,
		pucMAC,
		puiMACLength);
}

int SDF_HashInit(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength)
{
	return sdf->HashInit(
		hSessionHandle,
		uiAlgID,
		pucPublicKey,
		pucID,
		uiIDLength);
}

int SDF_HashUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength)
{
	return sdf->HashUpdate(
		hSessionHandle,
		pucData,
		uiDataLength);
}

int SDF_HashFinal(void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength)
{
	return sdf->HashFinal(
		hSessionHandle,
		pucHash,
		puiHashLength);
}

int SDF_CreateFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiFileSize)
{
	return sdf->CreateFile(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiFileSize);
}

int SDF_ReadFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int *puiReadLength,
	unsigned char *pucBuffer)
{
	return sdf->ReadFile(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiOffset,
		puiReadLength,
		pucBuffer);
}

int SDF_WriteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int uiWriteLength,
	unsigned char *pucBuffer)
{
	return sdf->WriteFile(
		hSessionHandle,
		pucFileName,
		uiNameLen,
		uiOffset,
		uiWriteLength,
		pucBuffer);
}

int SDF_DeleteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen)
{
	return sdf->DeleteFile(
		hSessionHandle,
		pucFileName,
		uiNameLen);
}

