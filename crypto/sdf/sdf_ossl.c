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

#include "sdf_lcl.h"

int SDF_LoadModule(SDF_METHOD *sdf, DSO *dso)
{
	sdf->OpenDevice = gmssl_SDF_OpenDevice;
	sdf->CloseDevice = gmssl_SDF_CloseDevice;
	sdf->OpenSession = gmssl_SDF_OpenSession;
	sdf->CloseSession = gmssl_SDF_CloseSession;
	sdf->GetDeviceInfo = gmssl_SDF_GetDeviceInfo;
	sdf->GenerateRandom = gmssl_SDF_GenerateRandom;
	sdf->GetPrivateKeyAccessRight = gmssl_SDF_GetPrivateKeyAccessRight;
	sdf->ReleasePrivateKeyAccessRight = gmssl_SDF_ReleasePrivateKeyAccessRight;
	sdf->ExportSignPublicKey_RSA = gmssl_SDF_ExportSignPublicKey_RSA;
	sdf->ExportEncPublicKey_RSA = gmssl_SDF_ExportEncPublicKey_RSA;
	sdf->GenerateKeyPair_RSA = gmssl_SDF_GenerateKeyPair_RSA;
	sdf->GenerateKeyWithIPK_RSA = gmssl_SDF_GenerateKeyWithIPK_RSA;
	sdf->GenerateKeyWithEPK_RSA = gmssl_SDF_GenerateKeyWithEPK_RSA;
	sdf->ImportKeyWithISK_RSA = gmssl_SDF_ImportKeyWithISK_RSA;
	sdf->ExchangeDigitEnvelopeBaseOnRSA = gmssl_SDF_ExchangeDigitEnvelopeBaseOnRSA;
	sdf->ExportSignPublicKey_ECC = gmssl_SDF_ExportSignPublicKey_ECC;
	sdf->ExportEncPublicKey_ECC = gmssl_SDF_ExportEncPublicKey_ECC;
	sdf->GenerateKeyPair_ECC = gmssl_SDF_GenerateKeyPair_ECC;
	sdf->GenerateKeyWithIPK_ECC = gmssl_SDF_GenerateKeyWithIPK_ECC;
	sdf->GenerateKeyWithEPK_ECC = gmssl_SDF_GenerateKeyWithEPK_ECC;
	sdf->ImportKeyWithISK_ECC = gmssl_SDF_ImportKeyWithISK_ECC;
	sdf->GenerateAgreementDataWithECC = gmssl_SDF_GenerateAgreementDataWithECC;
	sdf->GenerateKeyWithECC = gmssl_SDF_GenerateKeyWithECC;
	sdf->GenerateAgreementDataAndKeyWithECC = gmssl_SDF_GenerateAgreementDataAndKeyWithECC;
	sdf->ExchangeDigitEnvelopeBaseOnECC = gmssl_SDF_ExchangeDigitEnvelopeBaseOnECC;
	sdf->GenerateKeyWithKEK = gmssl_SDF_GenerateKeyWithKEK;
	sdf->ImportKeyWithKEK = gmssl_SDF_ImportKeyWithKEK;
	sdf->DestroyKey = gmssl_SDF_DestroyKey;
	sdf->ExternalPublicKeyOperation_RSA = gmssl_SDF_ExternalPublicKeyOperation_RSA;
	sdf->InternalPublicKeyOperation_RSA = gmssl_SDF_InternalPublicKeyOperation_RSA;
	sdf->InternalPrivateKeyOperation_RSA = gmssl_SDF_InternalPrivateKeyOperation_RSA;
	sdf->ExternalVerify_ECC = gmssl_SDF_ExternalVerify_ECC;
	sdf->InternalSign_ECC = gmssl_SDF_InternalSign_ECC;
	sdf->InternalVerify_ECC = gmssl_SDF_InternalVerify_ECC;
	sdf->ExternalEncrypt_ECC = gmssl_SDF_ExternalEncrypt_ECC;
	sdf->ExternalDecrypt_ECC = gmssl_SDF_ExternalDecrypt_ECC;
	sdf->InternalEncrypt_ECC = gmssl_SDF_InternalEncrypt_ECC;
	sdf->InternalDecrypt_ECC = gmssl_SDF_InternalDecrypt_ECC;
	sdf->Encrypt = gmssl_SDF_Encrypt;
	sdf->Decrypt = gmssl_SDF_Decrypt;
	sdf->CalculateMAC = gmssl_SDF_CalculateMAC;
	sdf->HashInit = gmssl_SDF_HashInit;
	sdf->HashUpdate = gmssl_SDF_HashUpdate;
	sdf->HashFinal = gmssl_SDF_HashFinal;
	sdf->CreateFile = gmssl_SDF_CreateFile;
	sdf->ReadFile = gmssl_SDF_ReadFile;
	sdf->WriteFile = gmssl_SDF_WriteFile;
	sdf->DeleteFile = gmssl_SDF_WriteFile;

	return 1;
}

