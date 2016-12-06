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

#ifndef HEADER_SDF_LCL_H
#define HEADER_SDF_LCL_H

#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

int gmssl_SDF_OpenDevice(
	void **phDeviceHandle);

/* Close the opened device handle
 * This function might failed.
 */
int gmssl_SDF_CloseDevice(
	void *hDeviceHandle);

/*
 * Unlike the `SDF_OpenDevice`, we always assume that the `SDF_OpenSession` can
 * be called multiple times, and the implementation will always return a new
 * session handle on success. But noramlly the hardware and the software can
 * only support limited sessions, so this function can also failed.
 *
 * For portability, the application should assume that only one cryptographic
 * operation can be processed over one session. For example, do not mix
 * symmetric encryption and hash functions over the same session. The
 * implementation might support multiple operations, check the vendor's manual.
 */
int gmssl_SDF_OpenSession(
	void *hDeviceHandle,
	void **phSessionHandle);

int gmssl_SDF_CloseSession(
	void *hSessionHandle);

int gmssl_SDF_GetDeviceInfo(
	void *hSessionHandle,
	DEVICEINFO *pstDeviceInfo);

int gmssl_SDF_GenerateRandom(
	void *hSessionHandle,
	unsigned int uiLength,
	unsigned char *pucRandom);

/*
 * In the standard GM/T 0018, the value of `uiKeyIndex` should start from 1,
 * and the maximum value is defined by the vendor.
 * The password length should be at least 8-byte.
 */
int gmssl_SDF_GetPrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucPassword,
	unsigned int uiPwdLength);

int gmssl_SDF_ReleasePrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex);

/*
 *                           Key Management Functions
 *
 * Functions:
 *	`SDF_ExportSignPublicKey_RSA`
 *	`SDF_ExportEncPublicKey_RSA`
 *	`SDF_GenerateKeyPair_RSA`
 *	`
 */


/* Export RSA signing public key */
int gmssl_SDF_ExportSignPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey);

/* Export RSA encryption public key */
int gmssl_SDF_ExportEncPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey);

/*
 * Generate RSA key pair.
 * The MAX RSA bits is defined as 2048 in GM/T 0018-2012. As 1024 is not very
 * secure, applications should always use 2048-bit. Use 1024-bit only for
 * legacy applications.
 */
int gmssl_SDF_GenerateKeyPair_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey);

/*
 * In a cryptographic API the symmetric keys (and otehr keys) can be
 * classified into session keys and storage keys. The storage keys will be
 * persistantly stored in the secure storage of a cryptograhic hardware
 * device. While the session keys only exist in the session period, after
 * the session is finished, it will be destroyed even if the symmetric key
 * operations are performed inside the hardware.
 *
 * The `gmapi` module only support session keys.
 */
/*
 * In the current version of GmSSL (2.x), the session keys will be kept in
 * the host memory intead of the cryptographic hardware's internal memory.
 * So the key handle will suffer memory attacks.
 */

/*
 * Generate a symmetric key with bit length `uiKeyBits`, encrypt the key data
 * with an internal RSA public key with index `uiIPKIndex`, output the
 * encrypted key data to buffer `pucKey` and length `puiKeyLength`, also return
 * the handle of the generated key `phKeyHandle`.
 */
int gmssl_SDF_GenerateKeyWithIPK_RSA(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle);

/*
 * Generate a symmetric key with bit length `uiKeyBits`, encrypt the key data
 * with an external RSA public key with data `pucPublicKey` in format
 * `RSArefPublickey`, output the encrypted key data to buffer `pucKey` and
 * length `puiKeyLength`, also return the handle `phKeyHandle` of the generated
 * key.
 */
int gmssl_SDF_GenerateKeyWithEPK_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle);

/*
 * Import the encrypted key generated from `SDF_GenerateKeyWithIPK_RSA` to the
 * session context, the internal RSA key index `uiISKIndex` should be the same
 * index of the parameter `uiIPKIndex` of `SDF_GenerateKeyWithIPK_RSA`.
 */
int gmssl_SDF_ImportKeyWithISK_RSA(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle);

/*
 * Convert internal public key encrypted symmetric key into ciphertext
 * encrypted by external public key. The input `pucDEInput` is the symmetric
 * key encrypted by internal public key `uiKeyIndex`. The output `pucDEOutput`
 * is encrypted under the external public key `pucPublicKey`.
 *
 * Note: This function is very dangerous. It convert a well protected symmetric
 * key into a state with security unknown. If the external private key is not
 * well protected, this function is the same as to unwrap of the symmetric key
 * and output the plaintext.
 */
int gmssl_SDF_ExchangeDigitEnvelopeBaseOnRSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDEInput,
	unsigned int uiDELength,
	unsigned char *pucDEOutput,
	unsigned int *puiDELength);

int gmssl_SDF_ExportSignPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey);

int gmssl_SDF_ExportEncPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey);

int gmssl_SDF_GenerateKeyPair_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int  uiKeyBits,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey);

int gmssl_SDF_GenerateKeyWithIPK_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	ECCCipher *pucKey,
	void **phKeyHandle);

int gmssl_SDF_GenerateKeyWithEPK_ECC(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucKey,
	void **phKeyHandle);

int gmssl_SDF_ImportKeyWithISK_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	ECCCipher *pucKey,
	void **phKeyHandle);

int gmssl_SDF_GenerateAgreementDataWithECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	void **phAgreementHandle);

int gmssl_SDF_GenerateKeyWithECC(
	void *hSessionHandle,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void *hAgreementHandle,
	void **phKeyHandle);

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
	void **phKeyHandle);

int gmssl_SDF_ExchangeDigitEnvelopeBaseOnECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucEncDataIn,
	ECCCipher *pucEncDataOut);

int gmssl_SDF_GenerateKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle);

int gmssl_SDF_ImportKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle);

int gmssl_SDF_DestroyKey(
	void *hSessionHandle,
	void *hKeyHandle);

/*
 * The RSA Operations include
 *	`SDF_ExternalPublicKeyOperation_RSA`
 *	`SDF_InternalPublicKeyOperation_RSA`
 *	`SDF_InternalPrivateKeyOperation_RSA`
 *
 * Noramlly RSA operations should be working with some padding methods, such
 * as PKCS #1 OAEP padding or PSS padding. As the SDF API does not provide any
 * parameter to set padding method, and it is neither specified in the GM/T
 * 0018-2012 standard, application developers need to ask the vendor or try
 * testing. The GmSSL SDF implementation will always try to use the PKCS #1
 * padding, but the underlying ENGINEs might not support this padding options.
 *
 * It should be noted that the SDF API does not support external private key
 * operations.
 */

/* RSA encryption or verification with external public key */
int gmssl_SDF_ExternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength);

/* RSA encryption or verification with internal public key */
int gmssl_SDF_InternalPublicKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength);

/* RSA decryption or signing with external private key */
int gmssl_SDF_InternalPrivateKeyOperation_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int *puiOutputLength);

/*
 * For all the ECC signing/verification, the to be signed data `pucData`
 * should be the digest of the message, instead of the original message. If
 * the application requires a GM standard signature with the hashed identity
 * `Z`, then `SDF_HashInit` must be called with the `pucPublicKey` and
 * `pucID` provided.
 */

/*
 * some of these functions require an `uiAlgID` to specify the algorithm.
 * Currently only `SGD_SM2_1` and `SGD_SM2_3` should be used. Maybe for some
 * implementations might also support international algorithms such as ECDSA
 * and ECIES.
 */

/* Verify SM2 siganture with external ECC public key */
int gmssl_SDF_ExternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	ECCSignature *pucSignature);

/* Generate SM2 signature with internal ECC private key */
int gmssl_SDF_InternalSign_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature);

/* Verify SM2 signature with internal ECC public key */
int gmssl_SDF_InternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature);

/*
 * there are limits on the max size of input plaintext, for SM2 encryptions,
 * the length will be equal to the `ECCref_MAX_CIPHER_LEN`
 */

/* Perform SM2 encryption with external ECC public key */
int gmssl_SDF_ExternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData);

/* Perform SM2 decryption with external ECC private key */
int gmssl_SDF_ExternalDecrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPrivateKey *pucPrivateKey,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int *puiDataLength);

/* Perform SM2 encryption with internal ECC public key */
int gmssl_SDF_InternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiAlgID,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData);

/* Perform SM2 decryption with internal ECC private key */
int gmssl_SDF_InternalDecrypt_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiAlgID,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int *puiDataLength);

/*
 * Symmetric Encryption:
 *	`SDF_Encrypt`
 *	`SDF_Decrypt`
 *
 * we will not provide two-step operations for SDF API which means the
 * caller can not assign the `pucEnData` to be NULL hoping that the API will
 * return the proper out length through `*puiEncDataLength`. The reason is
 * that the maximum output length can be easily estimated in almost all the
 * APIs of SDF. So when `pucEncData` is NULL or `*puiEncDataLength` is not
 * large enough, the API will just return with an error.
 *
 * The implementation will not carefully to estimate the output length, so
 * always prepare the max output buffer. For exmaple, prepare at least two
 * extra blocks for symmetric encryption, prepare max digest length of known
 * hash functions as the MAC buffer size.
 *
 * Note: the GM/T 0018-2012 standard requires the implementation MUST NOT do
 * any padding operatons, and the input data length should be multiple block
 * length. Thus these two functions can be used for modes such as CBC, the
 * caller can use a function more than once and do the padding himself.
 */

int gmssl_SDF_Encrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength);

int gmssl_SDF_Decrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength);

/*
 *                              MAC
 *
 * The scheme is a block cipher based MAC, default is CBC-MAC, might be
 * changed to more secure CMAC. These two MAC schemes do not support IV,
 * so the current implementation will omit the arugemnt `pucIV`. Be sure to
 * assign `NULL` to `pucIV`, if anything changed in the future, the API will
 * return errors to indicate the miss of `pucIV`.
 */
int gmssl_SDF_CalculateMAC(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucMAC,
	unsigned int *puiMACLength);


/*
 *                             Message Hashing
 *
 * Hashing Operations
 *	`SDF_HashInit`
 *	`SDF_HashUpdate`
 *	`SDF_HashFinal`
 */

/*
 * If the `pucPublicKey` is not NULL, `pucID` must not be NULL.
 * If caller need the ID to be default value, set the `pucID` to be
 * "1234567812345678" and the `uiIDLength` to be 16, this is the default
 * value defined in GM standards.
 */
int gmssl_SDF_HashInit(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength);

int gmssl_SDF_HashUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength);

int gmssl_SDF_HashFinal(void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength);

/*
 * File Operations:
 *	`SDF_CreateFile`
 *	`SDF_ReadFile`
 *	`SDF_WriteFile`
 *	`SDF_DeleteFile`
 *
 * Files in SDF API can be seen as small flash memory buffers inside the crypto
 * device referenced by a string. This subset of the SDF APIs lacks some
 * functionalities such as access control and metadata management. So the
 * storage should not be seen as secure storage, and data read from a file
 * should be checked before used.
 */

int gmssl_SDF_CreateFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen, /* max 128-byte */
	unsigned int uiFileSize);

int gmssl_SDF_ReadFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int *puiReadLength,
	unsigned char *pucBuffer);

int gmssl_SDF_WriteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int uiWriteLength,
	unsigned char *pucBuffer);

int gmssl_SDF_DeleteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen);



typedef struct {
	char *app;
	EVP_MD_CTX *md_ctx;
	ENGINE *engine;
} SDF_SESSION;

typedef struct {
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned int keylen;
} SDF_KEY;

const EVP_CIPHER *sdf_get_cipher(
	SDF_SESSION *session,
	unsigned int uiAlgoID);

const EVP_MD *sdf_get_digest(
	SDF_SESSION *session,
	unsigned int uiAlgoID);

EVP_PKEY *sdf_load_rsa_public_key(
	SDF_SESSION *session,
	unsigned int uiKeyIndex,
	unsigned int uiKeyUsage);

EVP_PKEY *sdf_load_rsa_private_key(
	SDF_SESSION *session,
	unsigned int uiKeyIndex,
	unsigned int uiKeyUsage);

EVP_PKEY *sdf_load_ec_public_key(
	SDF_SESSION *session,
	unsigned int uiKeyIndex,
	unsigned int uiKeyUsage);

EVP_PKEY *sdf_load_ec_private_key(
	SDF_SESSION *session,
	unsigned int uiKeyIndex,
	unsigned int uiKeyUsage);

int sdf_encode_ec_signature(
	ECCSignature *ref,
	unsigned char *out,
	size_t *outlen);

int sdf_decode_ec_signature(
	ECCSignature *ref,
	const unsigned char *in,
	size_t inlen);

#ifdef __cplusplus
}
#endif
#endif

