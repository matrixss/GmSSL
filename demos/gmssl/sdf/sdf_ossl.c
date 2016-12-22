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
	sdf->OpenDevice = SDF_OpenDevice;
	sdf->CloseDevice = SDF_CloseDevice;
	sdf->OpenSession = SDF_OpenSession;
	sdf->CloseSession = SDF_CloseSession;
	sdf->GetDeviceInfo = SDF_GetDeviceInfo;
	sdf->GenerateRandom = SDF_GenerateRandom;
	sdf->GetPrivateKeyAccessRight = SDF_GetPrivateKeyAccessRight;
	sdf->ReleasePrivateKeyAccessRight = SDF_ReleasePrivateKeyAccessRight;
	sdf->ExportSignPublicKey_RSA = SDF_ExportSignPublicKey_RSA;
	sdf->ExportEncPublicKey_RSA = SDF_ExportEncPublicKey_RSA;
	sdf->GenerateKeyPair_RSA = SDF_GenerateKeyPair_RSA;
	sdf->GenerateKeyWithIPK_RSA = SDF_GenerateKeyWithIPK_RSA;
	sdf->GenerateKeyWithEPK_RSA = SDF_GenerateKeyWithEPK_RSA;
	sdf->ImportKeyWithISK_RSA = SDF_ImportKeyWithISK_RSA;
	sdf->ExchangeDigitEnvelopeBaseOnRSA = SDF_ExchangeDigitEnvelopeBaseOnRSA;
	sdf->ExportSignPublicKey_ECC = SDF_ExportSignPublicKey_ECC;
	sdf->ExportEncPublicKey_ECC = SDF_ExportEncPublicKey_ECC;
	sdf->GenerateKeyPair_ECC = SDF_GenerateKeyPair_ECC;
	sdf->GenerateKeyWithIPK_ECC = SDF_GenerateKeyWithIPK_ECC;
	sdf->GenerateKeyWithEPK_ECC = SDF_GenerateKeyWithEPK_ECC;
	sdf->ImportKeyWithISK_ECC = SDF_ImportKeyWithISK_ECC;
	sdf->GenerateAgreementDataWithECC = SDF_GenerateAgreementDataWithECC;
	sdf->GenerateKeyWithECC = SDF_GenerateKeyWithECC;
	sdf->GenerateAgreementDataAndKeyWithECC = SDF_GenerateAgreementDataAndKeyWithECC;
	sdf->ExchangeDigitEnvelopeBaseOnECC = SDF_ExchangeDigitEnvelopeBaseOnECC;
	sdf->GenerateKeyWithKEK = SDF_GenerateKeyWithKEK;
	sdf->ImportKeyWithKEK = SDF_ImportKeyWithKEK;
	sdf->DestroyKey = SDF_DestroyKey;
	sdf->ExternalPublicKeyOperation_RSA = SDF_ExternalPublicKeyOperation_RSA;
	sdf->InternalPublicKeyOperation_RSA = SDF_InternalPublicKeyOperation_RSA;
	sdf->InternalPrivateKeyOperation_RSA = SDF_InternalPrivateKeyOperation_RSA;
	sdf->ExternalVerify_ECC = SDF_ExternalVerify_ECC;
	sdf->InternalSign_ECC = SDF_InternalSign_ECC;
	sdf->InternalVerify_ECC = SDF_InternalVerify_ECC;
	sdf->ExternalEncrypt_ECC = SDF_ExternalEncrypt_ECC;
	sdf->ExternalDecrypt_ECC = SDF_ExternalDecrypt_ECC;
	sdf->InternalEncrypt_ECC = SDF_InternalEncrypt_ECC;
	sdf->InternalDecrypt_ECC = SDF_InternalDecrypt_ECC;
	sdf->Encrypt = SDF_Encrypt;
	sdf->Decrypt = SDF_Decrypt;
	sdf->CalculateMAC = SDF_CalculateMAC;
	sdf->HashInit = SDF_HashInit;
	sdf->HashUpdate = SDF_HashUpdate;
	sdf->HashFinal = SDF_HashFinal;
	sdf->CreateFile = SDF_CreateFile;
	sdf->ReadFile = SDF_ReadFile;
	sdf->WriteFile = SDF_WriteFile;
	sdf->DeleteFile = SDF_WriteFile;

	return 1;
}

