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


int SDF_LoadModule(SDF_METHOD *sdf, DSO *dso)
{
	sdf->OpenDevice = DSO_bind_func(dso, "SDF_OpenDevice");
	sdf->CloseDevice = DSO_bind_func(dso, "SDF_CloseDevice");
	sdf->OpenSession = DSO_bind_func(dso, "SDF_OpenSession");
	sdf->CloseSession = DSO_bind_func(dso, "SDF_CloseSession");
	sdf->GetDeviceInfo = DSO_bind_func(dso, "SDF_GetDeviceInfo");
	sdf->GenerateRandom = DSO_bind_func(dso, "SDF_GenerateRandom");
	sdf->GetPrivateKeyAccessRight = DSO_bind_func(dso, "SDF_GetPrivateKeyAccessRight");
	sdf->ReleasePrivateKeyAccessRight = DSO_bind_func(dso, "SDF_ReleasePrivateKeyAccessRight");
	sdf->ExportSignPublicKey_RSA = DSO_bind_func(dso, "SDF_ExportSignPublicKey_RSA");
	sdf->ExportEncPublicKey_RSA = DSO_bind_func(dso, "SDF_ExportEncPublicKey_RSA");
	sdf->GenerateKeyPair_RSA = DSO_bind_func(dso, "SDF_GenerateKeyPair_RSA");
	sdf->GenerateKeyWithIPK_RSA = DSO_bind_func(dso, "SDF_GenerateKeyWithIPK_RSA");
	sdf->GenerateKeyWithEPK_RSA = DSO_bind_func(dso, "SDF_GenerateKeyWithEPK_RSA");
	sdf->ImportKeyWithISK_RSA = DSO_bind_func(dso, "SDF_ImportKeyWithISK_RSA");
	sdf->ExchangeDigitEnvelopeBaseOnRSA = DSO_bind_func(dso, "SDF_ExchangeDigitEnvelopeBaseOnRSA");
	sdf->ExportSignPublicKey_ECC = DSO_bind_func(dso, "SDF_ExportSignPublicKey_ECC");
	sdf->ExportEncPublicKey_ECC = DSO_bind_func(dso, "SDF_ExportEncPublicKey_ECC");
	sdf->GenerateKeyPair_ECC = DSO_bind_func(dso, "SDF_GenerateKeyPair_ECC");
	sdf->GenerateKeyWithIPK_ECC = DSO_bind_func(dso, "SDF_GenerateKeyWithIPK_ECC");
	sdf->GenerateKeyWithEPK_ECC = DSO_bind_func(dso, "SDF_GenerateKeyWithEPK_ECC");
	sdf->ImportKeyWithISK_ECC = DSO_bind_func(dso, "SDF_ImportKeyWithISK_ECC");
	sdf->GenerateAgreementDataWithECC = DSO_bind_func(dso, "SDF_GenerateAgreementDataWithECC");
	sdf->GenerateKeyWithECC = DSO_bind_func(dso, "SDF_GenerateKeyWithECC");
	sdf->GenerateAgreementDataAndKeyWithECC = DSO_bind_func(dso, "SDF_GenerateAgreementDataAndKeyWithECC");
	sdf->ExchangeDigitEnvelopeBaseOnECC = DSO_bind_func(dso, "SDF_ExchangeDigitEnvelopeBaseOnECC");
	sdf->GenerateKeyWithKEK = DSO_bind_func(dso, "SDF_GenerateKeyWithKEK");
	sdf->ImportKeyWithKEK = DSO_bind_func(dso, "SDF_ImportKeyWithKEK");
	sdf->DestroyKey = DSO_bind_func(dso, "SDF_DestroyKey");
	sdf->ExternalPublicKeyOperation_RSA = DSO_bind_func(dso, "SDF_ExternalPublicKeyOperation_RSA");
	sdf->InternalPublicKeyOperation_RSA = DSO_bind_func(dso, "SDF_InternalPublicKeyOperation_RSA");
	sdf->InternalPrivateKeyOperation_RSA = DSO_bind_func(dso, "SDF_InternalPrivateKeyOperation_RSA");
	sdf->ExternalVerify_ECC = DSO_bind_func(dso, "SDF_ExternalVerify_ECC");
	sdf->InternalSign_ECC = DSO_bind_func(dso, "SDF_InternalSign_ECC");
	sdf->InternalVerify_ECC = DSO_bind_func(dso, "SDF_InternalVerify_ECC");
	sdf->ExternalEncrypt_ECC = DSO_bind_func(dso, "SDF_ExternalEncrypt_ECC");
	sdf->ExternalDecrypt_ECC = DSO_bind_func(dso, "SDF_ExternalDecrypt_ECC");
	sdf->InternalEncrypt_ECC = DSO_bind_func(dso, "SDF_InternalEncrypt_ECC");
	sdf->InternalDecrypt_ECC = DSO_bind_func(dso, "SDF_InternalDecrypt_ECC");
	sdf->Encrypt = DSO_bind_func(dso, "SDF_Encrypt");
	sdf->Decrypt = DSO_bind_func(dso, "SDF_Decrypt");
	sdf->CalculateMAC = DSO_bind_func(dso, "SDF_CalculateMAC");
	sdf->HashInit = DSO_bind_func(dso, "SDF_HashInit");
	sdf->HashUpdate = DSO_bind_func(dso, "SDF_HashUpdate");
	sdf->HashFinal = DSO_bind_func(dso, "SDF_HashFinal");
	sdf->CreateFile = DSO_bind_func(dso, "SDF_CreateFile");
	sdf->ReadFile = DSO_bind_func(dso, "SDF_ReadFile");
	sdf->WriteFile = DSO_bind_func(dso, "SDF_WriteFile");
	sdf->DeleteFile = DSO_bind_func(dso, "SDF_WriteFile");

	return 1;
}

