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
#include <openssl/saf.h>
#include <openssl/gmapi.h>

static int test_saf(void)
{

	void *hAppHandle = NULL;
	char *pucCfgFilePath = "/usr/local/openssl/openss.cnf";
	unsigned int uiVersion = 0;
	unsigned int uiUsrType = 1; /* 0 for admin, 1 for user */
	unsigned char pucContainerName[] = "ContainerName";
	unsigned int uiContainerNameLen = sizeof(pucContainerName) - 1;
	unsigned char pucPin[] = "12345678";
	unsigned int uiPinLen = sizeof(pucPin) - 1;
	unsigned int uiRemainCount = 0;
	unsigned int uiCount1;
	unsigned int uiCount2;

	/* input certificate */
	unsigned char pucRootCaCertificate[] = "Change this";
	unsigned int uiRootCaCertificateLen = sizeof(pucRootCaCertificate);
	unsigned int uiCertIndex;
	unsigned char pucCaCertificate[] = "Change Me";
	unsigned int uiCaCertificateLen = sizeof(pucCaCertificate);
	unsigned char pucUsrCertificate[] = "hello";
	unsigned int uiUsrCertificateLen = sizeof(pucUsrCertificate);

	/* output certificate buffer */
	unsigned char pucCertificate[2048]; /* for output buffer */
	unsigned int uiCertificateLen = sizeof(pucCertificate);

	/* input CRL */
	unsigned char pucDerCrl[] = "change";
	unsigned int uiDerCrlLen = sizeof(pucDerCrl);

	if ((rv = SAF_Initialize(
		&hAppHandle,
		pucCfgFilePath)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Finalize(
		hAppHandle)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GetVersion(
		&uiVersion)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	printf("SAF API Version = %08X\n", uiVersion);

	if ((rv = SAF_Login(
		hAppHandle,
		uiUsrType,
		pucContainerName,
		uiContainerNameLen,
		pucPin,
		uiPinLen,
		&uiRemainCount)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* change PIN with the same value */
	if ((rv = SAF_ChangePin(
		hAppHandle,
		uiUsrType,
		pucContainerName,
		uiContainerNameLen,
		pucPin,
		uiPinLen,
		pucPin,
		uiPinLen,
		&uiRemainCount)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Logout(
		hAppHandle,
		uiUsrType)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/*
	 * Root CA Certificate Management
	 */

	if ((rv = SAF_GetRootCaCertificateCount(
		hAppHandle,
		&uiCount1)) != SAR_Ok) {
	}
	printf("RootCaCertificateCount = %u\n", uiCount1);

	if ((rv = SAF_AddTrustedRootCaCertificate(
		hAppHandle,
		pucRootCaCertificate,
		uiRootCaCertificateLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GetRootCaCertificateCount(
		hAppHandle,
		&uiCount2)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	printf("RootCaCertificateCount = %u\n", uiCount2);

	/* check if the certificate count increase, then assign the new
	 * certificate index
	 */
	if (uiCount2 != uiCount1 + 1) {
		printf("RootCaCertificateCount increase error\n");
		return 0;
	}
	uiCertIndex = uiCount1;

	if ((rv = SAF_GetRootCaCertificate(
		hAppHandle,
		uiCertIndex,
		pucCertificate,
		&uiCertificateLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if (uiCertificateLen != uiRootCaCertificateLen ||
		memcmp(pucCertificate, pucRootCaCertificate,
			uiRootCaCertificateLen) != 0) {
		return 0;
	}

	// Parse the certificate with X.509/ASN.1

	if ((rv = SAF_RemoveRootCaCertificate(
		hAppHandle,
		uiCertIndex)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}


	/* CA Certificate Management
	 */

	if ((rv = SAF_GetCaCertificateCount(
		hAppHandle,
		&uiCount1)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	printf("CaCertificateCount = %u\n", uiCount1);

	if ((rv = SAF_AddCaCertificate(
		hAppHandle,
		pucCaCertificate,
		uiCertificateLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GetCaCertificateCount(
		hAppHandle,
		&uiCount2)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	printf("CaCertificateCount = %u\n", uiCount2);

	if (uiCount2 != uiCount1 + 1) {
		fprintf(stderr, "error: invalid new CaCertificateCount\n");
		return 0;
	}

	uiCertIndex = uiCount1;
	printf("New CaCertificateIndex = %u\n", uiCertIndex);

	uiCertificateLen = sizeof(pucCertificate);
	if ((rv = SAF_GetCaCertificate(
		hAppHandle,
		uiCertIndex,
		pucCertificate,
		&uiCertificateLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_RemoveCaCertificate(
		hAppHandle,
		uiCertIndex)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* CRL Management */

	if ((rv = SAF_AddCrl(
		hAppHandle,
		pucDerCrl,
		uiDerCrlLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}


	if ((rv = SAF_VerifyCertificate(
		hAppHandle,
		pucUsrCertificate,
		uiUsrCertificateLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_VerifyCertificateByCrl(
		hAppHandle,
		pucUsrCertificate,
		uiUsrCertificateLen,
		pucDerCrl,
		uiDerCrlLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	char *pcOcspHostURL = "http://sdfsdfdsf.com/ocsp";
	unsigned int uiOcspHostURLLen = strlen(pcOcspHostURL);
	unsigned char pucUsrCertificate[] = "helo";
	unsigned int uiUsrCertificateLen = sizeof(pucUsrCertificate);

	if ((rv = SAF_GetCertificateStateByOCSP(
		hAppHandle,
		pcOcspHostURL,
		uiOcspHostURLLen,
		pucUsrCertificate,
		uiUsrCertificateLen,
		pucCACertificate,
		uiCACertficateLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* LDAP Operations */
	char *pcLdapHostURL = "http://ladp.com";
	unsigned int uiLdapHostURLLen = strlen(pcLdapHostURL);
	unsigned char pucQueryDN[] = "hello";
	unsigned int uiQueryDNLen = sizeof(pucQueryDN) - 1;
	unsigned char pucCrlData[4096];
	unsigned int uiCrlDataLen;

	if ((rv = SAF_GetCertFromLdap(
		hAppHandle,
		pcLdapHostURL,
		uiLdapHostURLLen,
		pucQueryDN,
		uiQueryDNLen,
		pucCertificate,
	 	&uiOutCertificateLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	uiCrlDataLen = sizeof(pucCrlData);
	if ((rv = SAF_GetCrlFromLdap(
		hAppHandle,
		pcLdapHostURL,
		uiLdapHostURLLen,
		pucCertificate,
		uiCertificateLen,
		pucCrlData,
		&uiCrlDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* FIXME: there are many InfoTypes */
	if ((rv = SAF_GetCertificateInfo(
		hAppHandle,
		pucCertificate,
		uiCertificateLen,
		uiInfoType,
		pucInfo,
		&uiInfoLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GetExtTypeInfo(
		void *hAppHandle,
		pucDerCert,
		uiDerCertLen,
		uiInfoType,
		pucPriOid,
		uiPriOidLen,
		pucInfo,
		&uiInfoLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* Certificates */

	if ((rv = SAF_EnumCertificates(
		hAppHandle,
		usrCerts)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_EnumKeyContainerInfo(
		void *hAppHandle,
		SGD_KEYCONTAINERINFO_ENUMLIST *keyContainerInfo)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_EnumCertificatesFree(
		void *hAppHandle,
		SGD_USR_CERT_ENUMLIST *usrCerts)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_EnumKeyContainerInfoFree(
		void *hAppHandle,
		SGD_KEYCONTAINERINFO_ENUMLIST *keyContainerInfo)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* BASE64 */

	if ((rv = SAF_Base64_Encode(
		pucInData,
		puiInDataLen,
		pucOutData,
		&uiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Base64_Decode(
		pucInData,
		puiInDataLen,
		pucOutData,
		&uiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}


	void *hBase64Obj = NULL;

	if ((rv = SAF_Base64_CreateBase64Obj(
		&hBase64Obj)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Base64_DestroyBase64Obj(
		hBase64Obj)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Base64_EncodeUpdate(
		hBase64Obj,
		pucInData,
		puiInDataLen,
		pucOutData,
		uiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Base64_EncodeFinal(
		hBase64Obj,
		pucOutData,
		&uiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Base64_DecodeUpdate(
		hBase64Obj,
		pucInData,
		puiInDataLen,
		pucOutData,
		&uiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Base64_DecodeFinal(
		hBase64Obj,
		pucOutData,
		&uiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* Random */

	unsigned char pucRand[128];
	unsigned int uiRandLen = sizeof(pucRand);

	memset(pucRand, 0, uiRandLen);
	if ((rv = SAF_GenRandom(
		uiRandLen,
		pucRand)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}
	print_bytes(pucRand, uiRandLen);

	/* Hash Functions */

	if ((rv = SAF_Hash(
		uiAlgoType,
		pucInData,
		uiInDataLen,
		pucPublicKey,
		uiPublicKeyLen,
		pubID,
		ulIDLen,
		pucOutData,
		&uiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	void *hHashObj = NULL;
	if ((rv = SAF_CreateHashObj(
		&hHashObj,
		uiAlgoType,
		pucPublicKey,
		uiPublicKeyLen,
		pucID,
		ulIDLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_DestroyHashObj(
		void *phHashObj)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_HashUpdate(
		void *phHashObj,
		const pucInData,
		uiInDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_HashFinal(void *phHashObj,
		pucOutData,
		*uiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	/* RSA */

	if ((rv = SAF_GenRsaKeyPair(
		hAppHandle,
		pucRSAContainerName,
		uiRSAContainerNameLen,
		uiKeyBits,
		uiKeyUsage,
		uiExportFlag)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GetPublicKey(
		void *hAppHandle,
		pucContainerName,
		uiContainerNameLen,
		uiKeyUsage,
		pucPublicKey,
		*puiPublicKeyLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_RsaSign(
		void *hAppHandle,
		pucContainerName,
		uiContainerNameLen,
		uiHashAlgoType,
		pucInData,
		uiInDataLen,
		pucSignature,
		*puiSignatureLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_RsaSignFile(
		void *hAppHandle,
		pucContainerName,
		uiContainerNameLen,
		uiHashAlgoType,
		pucFileName,
		pucSignature,
		*puiSignatureLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_RsaVerifySign(
		uiHashAlgoType,
		pucPublicKey,
		uiPublicKeyLen,
		pucInData,
		uiInDataLen,
		pucSignature,
		uiSignatureLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_RsaVerifySignFile(
		uiHashAlgoType,
		pucPublicKey,
		uiPublicKeyLen,
		pucFileName,
		pucSignature,
		uiSignatureLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_VerifySignByCert(
		uiHashAlgoType,
		pucCertificate,
		uiCertificateLen,
		pucInData,
		uiInDataLen,
		pucSignature,
		uiSignatureLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GenEccKeyPair(
		void *hAppHandle,
		pucContainerName,
		uiContainerNameLen,
		uiKeyBits,
		uiKeyUsage,
		uiExportFlag)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GetEccPublicKey(
		void *hAppHandle,
		pucContainerName,
		uiContainerNameLen,
		uiKeyUsage,
		pucPublicKey,
		*puiPublicKeyLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_EccSign(
		void *hAppHandle,
		pucContainerName,
		uiContainerNameLen,
		uiAlgorithmID,
		pucInData,
		uiInDataLen,
		pucSignData,
		*puiSignDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_EccVerifySign(
		pucPublicKey,
		uiPublicKeyLen,
		uiAlgorithmID,
		pucInData,
		uiInDataLen,
		pucSignData,
		uiSignDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_EccPublicKeyEnc(
		pucPublicKey,
		uiPublicKeyLen,
		uiAlgorithmID,
		pucInData,
		uiInDataLen,
		pucOutData,
		*puiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_EccPublicKeyEncByCert(
		pucCertificate,
		uiCertificateLen,
		uiAlgorithmID,
		pucInData,
		uiInDataLen,
		pucOutData,
		*puiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_EccVerifySignByCert(
		uiAlgorithmID,
		pucCertificate,
		uiCertificateLen,
		pucInData,
		uiInDataLen,
		pucSignData,
		uiSignDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_CreateSymmKeyObj(
		void *hAppHandle,
		void **phSymmKeyObj,
		pucContainerName,
		uiContainerLen,
		pucIV,
		uiIVLen,
		uiEncOrDec,
		uiCryptoAlgID)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GenerateKeyWithEPK(
		void *hSymmKeyObj,
		pucPublicKey,
		uiPublicKeyLen,
		pucSymmKey,
		uiSymmKeyLen,
		void **phKeyHandle)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_ImportEncedKey(
		void *hSymmKeyObj,
		pucSymmKey,
		uiSymmKeyLen,
		void **phKeyHandle)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GenerateAgreementDataWithECC(
		void *hSymmKeyObj,
		uiISKIndex,
		uiKeyBits,
		pucSponsorID,
		uiSponsorIDLength,
		pucSponsorPublicKey,
		*puiSponsorPublicKeyLen,
		pucSponsorTmpPublicKey,
		*puiSponsorTmpPublicKeyLen,
		void **phAgreementHandle)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GenerateKeyWithECC(
		void *phAgreementHandle,
		pucResponseID,
		uiResponseIDLength,
		pucResponsePublicKey,
		uiResponsePublicKeyLen,
		pucResponseTmpPublicKey,
		uiResponseTmpPublicKeyLen,
		void **phKeyHandle)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_GenerateAgreementDataAdnKeyWithECC(
		void *hSymmKeyObj,
		uiISKIndex,
		uiKeyBits,
		pucResponseID,
		uiResponseIDLength,
		pucSponsorID,
		uiSponsorIDLength,
		pucSponsorPublicKey,
		*puiSponsorPublicKeyLen,
		pucSponsorTmpPublicKey,
		*puiSponsorTmpPublicKeyLen,
		pucResponsePublicKey,
		uiResponsePublicKeyLen,
		pucResponseTmpPublicKey,
		uiResponseTmpPublicKeyLen,
		void **phKeyHandle)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_DestroySymmAlgoObj(
		void *hSymmKeyObj)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_DestroyKeyHandle(
		void *hKeyHandle)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SymmEncrypt(
		void *hKeyHandle,
		const pucInData,
		uiInDataLen,
		pucOutData,
		*puiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SymmEncryptUpdate(
		void *hKeyHandle,
		const pucInData,
		uiInDataLen,
		pucOutData,
		*puiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SymmEncryptFinal(
		void *hKeyHandle,
		pucOutData,
		*puiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SymmDecrypt(
		void *hKeyHandle,
		pucInData,
		uiInDataLen,
		pucOutData,
		*puiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SymmDecryptUpdate(
		void *hKeyHandle,
		pucInData,
		uiInDataLen,
		pucOutData,
		*puiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SymmDecryptFinal(
		void *hKeyHandle,
		const pucInData,
		uiInDataLen,
		pucOutData,
		*puiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Mac(
		void *hKeyHandle,
		const pucInData,
		uiInDataLen,
		pucOutData,
		*puiOutDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_MacUpdate(
		void *hKeyHandle,
		const pucInData,
		uiInDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_MacFinal(
		void *hKeyHandle,
		pucOutData,
		*puiOutDataLen)) != SAR_Ok) {

		PRINT_ERRSTR(rv);
		return 0;
	}
	if ((rv = SAF_Pkcs7_EncodeData(
		void *hAppHandle,
		pucSignContainerName,
		uiSignContainerNameLen,
		uiSignKeyUsage,
		pucSignerCertificate,
		uiSignerCertificateLen,
		uiDigestAlgorithm,
		pucEncCertificate,
		uiEncCertificateLen,
		pucData,
		uiDataLen,
		pucDerP7Data,
		*puiDerP7DataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Pkcs7_DecodeData(
		void *hAppHandle)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Pkcs7_EncodeSignedData(
		void *hAppHandle,
		pucSignContainerName,
		uiSignContainerNameLen,
		uiSignKeyUsage,
		pucSignerCertificate,
		uiSignerCertificateLen,
		uiDigestAlgorithm,
		pucData,
		uiDataLen,
		pucDerP7Data,
		*puiDerP7DataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Pkcs7_DecodeSignedData(
		void *hAppHandle,
		pucDerP7SignedData,
		uiDerP7SignedDataLen,
		pucSignerCertificate,
		uiSignerCertificateLen,
		uiDigestAlgorithm,
		pucData,
		uiDataLen,
		pucSign,
		*puiSignLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Pkcs7_EncodeEnvelopedData(
		void *hAppHandle,
		pucData,
		uiDataLen,
		pucEncCertificate,
		uiEncCertificateLen,
		uiSymmAlgorithm,
		pucDerP7EnvelopedData,
		*puiDerP7EnvelopedDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Pkcs7_DecodeEnvelopedData(
		void *hAppHandle,
		pucDecContainerName,
		uiDecContainerNameLen,
		uiDecKeyUsage,
		pucDerP7EnvelopedData,
		uiDerP7EnvelopedDataLen,
		pucData,
		*puiDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Pkcs7_EncodeDigestedData(
		void *hAppHandle,
		uiDigestAlgorithm,
		pucData,
		uiDataLen,
		pucDerP7DigestedData,
		*puiDerP7DigestedDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_Pkcs7_DecodeDigestedData(
		void *hAppHandle,
		uiDigestAlgorithm,
		pucDerP7DigestedData,
		uiDerP7DigestedDataLen,
		pucData,
		uiDataLen,
		pucDigest,
		*puiDigestLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SM2_EncodeSignedAndEnvelopedData(
		void *hAppHandle,
		pucSignContainerName,
		uiSignContainerNameLen,
		uiSignKeyUsage,
		pucSignerCertificate,
		uiSignerCertificateLen,
		uiDigestAlgorithm,
		pucEncCertificate,
		uiEncCertificateLen,
		uiSymmAlgorithm,
		pucData,
		uiDataLen,
		pucDerSignedAndEnvelopedData,
		*puiDerSignedAndEnvelopedDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SM2_DecodeSignedAndEnvelopedData(
		void *hAppHandle,
		pucDerContainerName,
		uiDerContainerNameLen,
		uiDecKeyUsage,
		pucDerSignedAndEnvelopedData,
		uiDerSignedAndEnvelopedDataLen,
		pucData,
		*puiDataLen,
		pucSignerCertificate,
		*puiSignerCertificateLen,
		*puiDigestAlgorithms)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SM2_EncodeSignedData(
		void *hAppHandle,
		pucSignContainerName,
		uiSignContainerNameLen,
		uiSignKeyUsage,
		pucSignerCertificate,
		uiSignerCertificateLen,
		uiDigestAlgorithm,
		pucData,
		uiDataLen,
		pucDerSignedData,
		*puiDerSignedDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SM2_DecodeSignedData(
		void *hAppHandle,
		pucDerSignedData,
		uiDerSignedDataLen,
		pucSignerCertificate,
		uiSignerCertificateLen,
		uiDigestAlgorithm,
		pucData,
		uiDataLen,
		pucSign,
		*puiSignLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SM2_EncodeEnvelopedData(
		void *hAppHandle,
		pucData,
		uiDataLen,
		pucEncCertificate,
		uiEncCertificateLen,
		uiSymmAlgorithm,
		pucDerEnvelopedData,
		*puiDerEnvelopedDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

	if ((rv = SAF_SM2_DecodeEnvelopedData(
		void *hAppHandle,
		pucDecContainerName,
		uiDecContainerNameLen,
		uiDecKeyUsage,
		pucDerEnvelopedData,
		uiDerEnvelopedDataLen,
		pucData,
		*puiDataLen)) != SAR_Ok) {
		PRINT_ERRSTR(rv);
		return 0;
	}

}

int main(int argc, char **argv)
{
	(void)test_saf(void);
	return 0;
}

