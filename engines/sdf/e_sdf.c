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

/*                            SDF ENGINE
 *
 * With SDF ENGINEs, there might be multiple implementations of the SDF API.
 * One is the native implementation in `crypto/gmapi/sdf*`, the others are
 * coming from crypto hardware vendors with dynamic libraries (noramlly). To
 * keep multiple implementation is reasonable, because applications might
 * want to use multiple different cards together but with the same wrapping
 * API from GmSSL. For example, the vendor sansec provides different models,
 * some focusing on symmetric encryption acceleration, some focusing on
 * symmetric algorithm acceleration. And some users might plug multiple
 * cards for acceleration or different users.
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/ssf33.h>
#include <openssl/sm1.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/sms4.h>
#include <openssl/sm9.h>
#include <openssl/ossl_typ.h>
#include <openssl/sdf.h>
#include "e_sdf_err.h"
#include "e_sdf_err.c"



static void *hDeviceHandle = NULL;
static void *hSessionHandle = NULL;

static int sdf_idx = -1;
static int rsa_sign_sdf_idx = -1;
static int rsa_enc_sdf_idx = -1;
static int ec_sign_sdf_idx = -1;
static int ec_enc_sdf_idx = -1;
static int ec_dh_sdf_idx = -1;



/* Ctrl and Commands
 */



#define SDF_CMD_SO_PATH		ENGINE_CMD_BASE
#define SDF_CMD_OPEN_DEV	(ENGINE_CMD_BASE + 1)
#define SDF_CMD_DEV_AUTH	(ENGINE_CMD_BASE + 2)

static const ENGINE_CMD_DEFN sdf_cmd_defns[] = {
	{SDF_CMD_SO_PATH,
	 "SO_PATH",
	 "Specifies the path to the vendor's SDF shared library",
	 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_OPEN_DEV,
	 "OPEN_DEVICE",
	 "Connect SKF device with device name",
	 ENGINE_CMD_FLAG_STRING},
	{SKF_CMD_DEV_AUTH,
	 "DEV_AUTH",
	 "Authenticate to device with authentication key",
	 ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0},
};

static int sdf_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
	ESDFerr(ESDF_F_SDF_CTRL, ESKF_R_INVALID_CTRL_CMD);


	switch (cmd) {
	case SDF_CMD_USE_PRIVATE_KEY:
	}

	return 0;
}

/*                    Random Number Generator
 *
 * The SDF API provides function `SDF_GenerateRandom` for random number
 * generation. The `e_sdf` engine provides a simple wrapper of the SDF API.
 * While using the `e_sdf` random number generator should be careful,
 * because the security is totally depends on the SDF library vendors, and
 * the security level might be different between different vendors.
 * Another issue is that the SDF API does not provide generator seeding API,
 * so it can not be recovered from attacks. But it is a good choice to use
 * this engine as an extra entropy source to seed the default generator.
 */

static int sdf_rand_bytes(unsigned char *out, int outlen)
{
	if (!hDeviceHandle || !hSessionHandle) {
		ESDFerr(ESDF_F_SDF_RAND_BYTES, ESDF_R_SESSION_NOT_OPENED);
		return 0;
	}
	/* do not allow outlen == 0 for error detection */
	if (outlen <= 0) {
		ESDFerr(ESDF_F_SDF_RAND_BYTES, ESDF_R_INVALID_INPUT_LENGTH);
		return 0;
	}

	if (SDF_GenerateRandom(hSessionHandle, (unsigned int)outlen,
		out) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_RAND_BYTES, ESDF_R_SDF_GEN_RANDOM_FAILURE);
		return 0;
	}
	return 1;
}

/* the other engines implement this function */
static int sdf_rand_status(void)
{
	return 1;
}

/*
 * typedef struct {
 *	int (*seed)(const void *buf, int num);
 *	int (*bytes)(unsigned char *buf, int num);
 *	void (*cleanup)(void);
 *	int (*add)(const void *buf, int num, double entropy);
 *	int (*pseudorand)(unsigned char *buf, int num);
 *	int (*status)(void);
 * } RAND_METHOD;
 */

static RAND_METHOD sdf_rand = {
	NULL,
	sdf_rand_bytes,
	NULL,
	NULL,
	sdf_rand_bytes,
	sdf_rand_status,
};


/*                        Digest Algorithms
 *
 * The current GM API defines 3 digest algorithms, SHA-1, SHA-256 and SM3. The
 * digest functions of the SDF API also support the SM2 digest with signer's
 * identity string as input. The default `EVP_DigestInit/Update/Final` does not
 * support extra information such as the identity string, but this information
 * can be supplied with the `EVP_MD_CTX_ctrl`. The current `sdf` engine will
 * not provide this capability of the `SDF_HashInit`. Normally this capability,
 * even the support of hash functions, is not really required. But some
 * testing (like generate test vectors from the hardware) and benchmarking
 * might use the hardware implementation and the hash with SM2 identity.
 */

static int sdf_sm3_init(EVP_MD_CTX *ctx)
{
	if (!hSessionHandle) {
		ESDFerr(ESDF_F_SDF_SM3_INIT, ESDF_R_SESSION_NOT_OPENED);
		return 0;
	}
	if ((rv = SDF_HashInit(hSessionHandle, SGD_SM3,
		NULL, NULL, 0)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_SM3_INIT, ESDF_R_SDF_HASH_INIT);
		return 0;
	}
	return 1;
}

static int sdf_sha1_init(EVP_MD_CTX *ctx)
{
	if (!hSessionHandle) {
		ESDFerr(ESDF_F_SDF_SHA1_INIT, ESDF_R_SESSION_NOT_OPENED);
		return 0;
	}
	if ((rv = SDF_HashInit(hSessionHandle, SGD_SHA1,
		NULL, NULL, 0)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_SHA1_INIT, ESDF_R_SDF_HASH_INIT);
		return 0;
	}
	return 1;
}

static int sdf_sha256_init(EVP_MD_CTX *ctx)
{
	if (!hSessionHandle) {
		ESDFerr(ESDF_F_SDF_SHA256_INIT, ESDF_R_SESSION_NOT_OPENED);
		return 0;
	}
	if ((rv = SDF_HashInit(hSessionHandle, SGD_SHA256,
		NULL, NULL, 0)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_SHA256_INIT, ESDF_R_SDF_HASH_INIT);
		return 0;
	}
	return 1;
}

static int sdf_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
	int rv;
	if (!hSessionHandle) {
		ESDFerr(ESDF_F_SDF_DIGEST_UPDATE, ESDF_R_SESSION_NOT_OPENED);
		return 0;
	}
	if (!data) {
		ESDFerr(ESDF_F_SDF_DIGEST_UPDATE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (count <= 0 || count > INT_MAX) {
		ESDFerr(ESDF_F_SDF_DIGEST_UPDATE, ESDF_R_INVALID_LENGTH);
		return 0;
	}
	if ((rv = SDF_HashUpdate(hSessionHandle,
		data, (unsigned int)count)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_DIGEST_UPDATE, ESDF_R_SDF_HASH_UPDATE);
		return 0;
	}
	return 1;
}

static int sdf_digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	int rv;
	unsigned int mdlen;
	if (!hSessionHandle) {
		ESDFerr(ESDF_F_SDF_DIGEST_FINAL, ESDF_R_SESSION_NOT_OPENED);
		return 0;
	}
	if (!md) {
		ESDFerr(ESDF_F_SDF_DIGEST_FINAL, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	mdlen = EVP_MAX_MD_SIZE;
	if ((rv = SDF_HashFinal(hSessionHandle, md, &mdlen)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_DIGEST_FINAL, ESDF_R_SDF_HASH_FINAL);
		return 0;
	}
	return 1;
}

/* used to set SM2 id */
static int sdf_digest_set_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
	return 0;
}

static EVP_MD *sdf_sm3 = NULL;
static EVP_MD *sdf_sha1 = NULL;
static EVP_MD *sdf_sha256 = NULL;

/*
 * EVP_MD Set Functions:
 *	EVP_MD_meth_new/dup/free
 *	EVP_MD_meth_set_result_size
 *	EVP_MD_meth_set_input_blocksize
 *	EVP_MD_meth_set_app_datasize
 *	EVP_MD_meth_set_flags
 *	EVP_MD_meth_set_init/update/final
 *	EVP_MD_meth_set_copy/cleanup/ctrl
 */

static const EVP_MD *sdf_get_sm3(void)
{
	if (!sdf_sm3) {
		EVP_MD *md;
		if (!(md = EVP_MD_meth_new(NID_sm3, NID_sm2sign)) ||
			!EVP_MD_meth_set_result_size(md, SM3_DIGEST_LENGTH) ||
			!EVP_MD_meth_set_input_blocksize(md, SM3_CBLOCK) ||
			!EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *)) ||
			!EVP_MD_meth_set_flags(md, 0) ||
			!EVP_MD_meth_set_init(md, sdf_sm3_init) ||
			!EVP_MD_meth_set_update(md, sdf_digest_update) ||
			!EVP_MD_meth_set_final(md, sdf_digest_final) ||
			!EVP_MD_meth_set_ctrl(md, sdf_digest_ctrl)) {
			EVP_MD_meth_free(md);
			md = NULL
		}
		sdf_sm3 = md;
	}
	return sdf_sm3;
}

static const EVP_MD *sdf_get_sha1(void)
{
	if (!sdf_sha1) {
		EVP_MD *md;
		if (!(md = EVP_MD_meth_new(NID_sha1, NID_sm2sign)) ||
			!EVP_MD_meth_set_result_size(md, SHA1_DIGEST_LENGTH) ||
			!EVP_MD_meth_set_input_blocksize(md, SHA1_CBLOCK) ||
			!EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *)) ||
			!EVP_MD_meth_set_flags(md, 0) ||
			!EVP_MD_meth_set_init(md, sdf_sha1_init) ||
			!EVP_MD_meth_set_update(md, sdf_digest_update) ||
			!EVP_MD_meth_set_final(md, sdf_digest_final) ||
			!EVP_MD_meth_set_ctrl(md, sdf_digest_ctrl)) {
			EVP_MD_meth_free(md);
			md = NULL;
		}
		sdf_sha1 = md;
	}
	return sdf_sha1;
}

static const EVP_MD *sdf_get_sha256(void)
{
	if (!sdf_sha256) {
		EVP_MD *md;
		if (!(md = EVP_MD_meth_new(NID_sha256, NID_sm2sign)) ||
			!EVP_MD_meth_set_result_size(md, SHA256_DIGEST_LENGTH) ||
			!EVP_MD_meth_set_input_blocksize(md, SHA256_CBLOCK) ||
			!EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *)) ||
			!EVP_MD_meth_set_flags(md, 0) ||
			!EVP_MD_meth_set_init(md, sdf_sha256_init) ||
			!EVP_MD_meth_set_update(md, sdf_digest_update) ||
			!EVP_MD_meth_set_final(md, sdf_digest_final) ||
			!EVP_MD_meth_set_ctrl(md, sdf_digest_ctrl)) {
			EVP_MD_meth_free(md);
			md = NULL;
		}
		sdf_sha256 = md;
	}
	return sdf_sha256;
}

#define SDF_MAX_DIGESTS	8
static const int sdf_digest_nids[SDF_MAX_DIGESTS] = {0};

static int sdf_get_digest_nids(int **nids)
{
	DEVICEINFO devInfo;
	int rv;
	int i;

	if (!hDeviceHandle || !hSessionHandle) {
		ESDFerr(ESDF_F_SDF_GET_DIGEST_NIDS,
			ESDF_R_DEVICE_NOT_OPENED);
		return 0;
	}
	if (!hSessionHandle) {
		ESDFerr(ESDF_F_SDF_GET_DIGEST_NIDS,
			ESDF_R_SESSION_NOT_OPENED);
		return 0;
	}

	memset(&devInfo, 0, sizeof(devInfo));

	if ((rv = SDF_GetDeviceInfo(hSessionHandle, &devInfo)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_GET_DIGEST_NIDS,
			ESDF_R_GET_DEVICE_INFO_FAILURE);
		return 0;
	}

	memset(sdf_digest_nids, 0, sizeof(sdf_digest_nids));

	i = 0;
	if (devInfo.HashAlgAbility & SGD_SM3) {
		sdf_digest_nids[i++] = NID_sm3;
	}
	if (devInfo.HashAlgAbility & SGD_SHA1) {
		sdf_digest_nids[i++] = NID_sha1;
	}
	if (devInfo.HashAlgAbility & SGD_SHA256) {
		sdf_digest_nids[i++] = NID_sha256;
	}

	if (nids) {
		*nids = sdf_digest_nids;
	}
	return i;
}

static int sdf_is_digest_supported(int nid)
{
	const int *nids = NULL;
	int i, n;

	n = sdf_get_digest_nids(&nids);
	for (i = 0; i < n; i++) {
		if (nid == nids[i]) {
			return 1;
		}
	}

	return 0;
}

static int sdf_digests(ENGINE *e, const EVP_MD **digest,
	const int **nids, int nid)
{
	if (!digest) {
		return sdf_digest_nids(nids);
	}

	if (!sdf_is_digest_supported(nid)) {
		*digest = NULL;
		return 0;
	}

	switch (nid) {
	case NID_sm3:
		*digest = sdf_get_sm3();
		break;
	case NID_sha1:
		*digest = sdf_get_sha1();
		break;
	case NID_sha256:
		*digest = sdf_get_sha256();
		break;
	default:
		/* it will never happen because we haved checked this through
		 * `sdf_is_digest_supported`, keep this for protection */
		*digest = NULL;
		return 0;
	}

	return 1;
}


/*                           Ciphers
 *
 * The current GM API (SAF, SDF adn SKF) defines 3 block ciphers (SM1,
 * SSF33, SM4/SMS4) and 1 stream cipher ZUC, together with serveral
 * encryptoin modes. The SDF API provides two cipher related functions,
 * `SDF_Encrypt` and `SDF_Decrypt`. The supported ciphers can be retrieved
 * from the device information with the function `SDF_getDeviceInfo`.
 * But even if the cipher is supported,  the SDF API itself might not
 * guarantee all the encryption modes are supported.
 */

#define SDF_MAX_CIPHERS	32
static int sdf_cipher_nids[SDF_MAX_CIPHERS] = {0};

static int sdf_get_cipher_nids(const int **nids)
{
	DEVICEINFO devInfo;
	int i;

	if (!hDeviceHandle) {
		return 0;
	}
	if (!hSessionHandle) {
		return 0;
	}

	if ((rv = SDF_GetDeviceInfo(hSessionHandle, &devInfo)) != SDR_OK) {
		return 0;
	}

	i = 0;
	if (devInfo.SymAlgAbility & SGD_SM1) {
		sdf_cipher_nids[i++] = NID_sm1_ecb;
		sdf_cipher_nids[i++] = NID_sm1_cbc;
		sdf_cipher_nids[i++] = NID_sm1_cfb128;
		sdf_cipher_nids[i++] = NID_sm1_ofb128;
	}
	if (devInfo.SymAlgAbility & SGD_SSF33) {
		sdf_cipher_nids[i++] = NID_ssf33_ecb;
		sdf_cipher_nids[i++] = NID_ssf33_cbc;
		sdf_cipher_nids[i++] = NID_ssf33_cfb128;
		sdf_cipher_nids[i++] = NID_ssf33_ofb128;
	}
	if (devInfo.SymAlgAbility & SGD_SM4) {
		sdf_cipher_nids[i++] = NID_sms4_ecb;
		sdf_cipher_nids[i++] = NID_sms4_cbc;
		sdf_cipher_nids[i++] = NID_sms4_cfb128;
		sdf_cipher_nids[i++] = NID_sms4_ofb128;
	}
	if (devInfo.SymAlgAbility & SGD_ZUC) {
		sdf_cipher_nids[i++] = NID_zuc_eea3;
	}

	return i;
}

static int sdf_is_cipher_supported(int nid)
{
	const int *nids = NULL;
	int i, n;

	n = sdf_get_cipher_nids(&nids);
	for (i = 0; i < n; i++) {
		if (nid == nids[i]) {
			return 1;
		}
	}

	return 0;
}

static int sdf_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	int mode;
	mode = EVP_CIPHER_CTX_mode(ctx);
	if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
	}


}

/*
 * EVP_CIPHER_CTX_encrypting
 * EVP_CIPHER_CTX_nid
 * EVP_CIPHER_CTX_block_size
 * EVP_CIPHER_CTX_key_length
 * EVP_CIPHER_CTX_iv_length
 * EVP_CIPHER_CTX_iv
 * EVP_CIPHER_CTX_original_iv
 * EVP_CIPHER_CTX_iv_noconst
 * EVP_CIPHER_CTX_buf_noconst
 * EVP_CIPHER_CTX_num
 * EVP_CIPHER_get_app_data
 * EVP_CIPHER_get_cipher_data
 */
/*
501 int SDF_Encrypt(
502         void *hSessionHandle,
503         void *hKeyHandle,
504         unsigned int uiAlgID,
505         unsigned char *pucIV,
506         unsigned char *pucData,
507         unsigned int uiDataLength,
508         unsigned char *pucEncData,
509         unsigned int *puiEncDataLength);
510
*/
static int sdf_sm1_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	if (!EVP_CIPHER_CTX_set
}

static int sdf_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t inlen)
{

	if ((rv = SDF_Encrypt(hSessionHandle, hKeyHandle,
		uiAlgID,
		EVP_CIPHER_CTX_iv(ctx),
		in,
		inlen,
		out,
		&outlen)) != SDR_OK) {
	}

	return -1;
}

static int sdf_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{

}



static const EVP_CIPHER *sdf_ssm4_cbc(void)
{
}

/* EVP_CIPHER set functions:
 *	EVP_CIPHER_meth_new/dup/free
 *	EVP_CIPHER_meth_set_iv_length
 *	EVP_CIPHER_meth_set_flags
 *	EVP_CIPHER_meth_set_impl_ctx_size
 *	EVP_CIPHER_meth_set_init
 *	EVP_CIPHER_meth_set_do_cipher
 *	EVP_CIPHER_meth_set_cleanup
 *	EVP_CIPHER_meth_set_set_asn1_params
 *	EVP_CIPHER_meth_set_get_asn1_params
 *	EVP_CIPHER_meth_set_ctrl
 */

static EVP_CIPHER *sdf_ssf33_cbc = NULL;
static EVP_CIPHER *sdf_ssf33_cfb = NULL;
static EVP_CIPHER *sdf_ssf33_ofb = NULL;
static EVP_CIPHER *sdf_sm1_ecb = NULL;
static EVP_CIPHER *sdf_sm1_cbc = NULL;
static EVP_CIPHER *sdf_sm1_cfb = NULL;
static EVP_CIPHER *sdf_sm1_ofb = NULL;
static EVP_CIPHER *sdf_sms4_ecb = NULL;
static EVP_CIPHER *sdf_sms4_cbc = NULL;
static EVP_CIPHER *sdf_sms4_cfb = NULL;
static EVP_CIPHER *sdf_sms4_ofb = NULL;

/*
 226 int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
 227                              int (*init) (EVP_CIPHER_CTX *ctx,
 228                                           const unsigned char *key,
 229                                           const unsigned char *iv,
 230                                           int enc));
 231 int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
 232                                   int (*do_cipher) (EVP_CIPHER_CTX *ctx,
 233                                                     unsigned char *out,
 234                                                     const unsigned char *in,
 235                                                     size_t inl));
511 int SDF_Decrypt(
512         void *hSessionHandle,
513         void *hKeyHandle,
514         unsigned int uiAlgID,
515         unsigned char *pucIV,
516         unsigned char *pucEncData,
517         unsigned int uiEncDataLength,
518         unsigned char *pucData,
519         unsigned int *puiDataLength);
*/

static int sdf_ssf33_ecb_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t inlen)
{
	int rv;
	unsigned int outlen;

	if ((rv = SDF_Encrypt(hSessionHandle, hKeyHandle, uiAlgID,
		NULL, in, inlen, out, &outlen)) != SDR_OK) {
	}

	return 0;
}


static EVP_CIPHER *sdf_ssf33_ecb = NULL;
static const EVP_CIPHER *sdf_get_ssf33_ecb(void)
{
	if (!sdf_ssf33_ecb) {
		EVP_CIPHER *cipher;
		if (!(cipher = EVP_CIPHER_meth_new(NID_ssf33)) ||
			!EVP_CIPHER_meth_set_iv_length(cipher, SSF33_IV_LENGTH) ||
			!EVP_CIPHER_meth_set_flags(cipher, 0) ||
			!EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(EVP_CIPHER_CTX)) ||
			!EVP_CIPHER_meth_set_init(cipher, sdf_ssf33_init) ||
			!EVP_CIPHER_meth_set_do_cipher(cipher, sdf_do_cipher)) {
			EVP_CIPHER_meth_free(cipher);
			cipher = NULL;
		}
		sdf_ssf33_ecb = cipher;
	}
	return sdf_ssf33_ecb;
}

static int sdf_cipher_supported(int nid)
{
	return 0;
}

static int sdf_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
	const int **nids, int nid)
{
	if (!cipher) {
		*nids = sdf_cipher_nids;
		return sizeof(sdf_cipher_nids)/sizeof(sdf_cipher_nids[0]);
	}

	switch (nid) {
	case NID_ssf33_ecb:
		*cipher = &skf_ssf33_ecb;
		break;
	case NID_ssf33_cbc:
		*cipher = &skf_ssf33_cbc;
		break;
	case NID_ssf33_cfb128:
		*cipher = &skf_ssf33_cfb128;
		break;
	case NID_ssf33_ofb128:
		*cipher = &skf_ssf33_ofb128;
		break;
	case NID_sm1_ecb:
		*cipher = &skf_sm1_ecb;
		break;
	case NID_sm1_cbc:
		*cipher = &skf_sm1_cbc;
		break;
	case NID_sm1_cfb128:
		*cipher = &skf_sm1_cfb128;
		break;
	case NID_sm1_ofb128:
		*cipher = &skf_sm1_ofb128;
		break;
	case NID_sms4_ecb:
		*cipher = &skf_sms4_ecb;
		break;
	case NID_sms4_cbc:
		*cipher = &skf_sms4_cbc;
		break;
	case NID_sms4_cfb128:
		*cipher = &skf_sms4_cfb128;
		break;
	case NID_sms4_ofb128:
		*cipher = &skf_sms4_ofb128;
		break;

	default:
		*cipher = NULL;
		return 0;
	}

}



typedef struct SDF_PRIVKEY_st
	unsigned int uiKeyIndex;
	unsigned int uiKeyUsage;
} SDF_PRIVKEY;

static int sdf_init(ENGINE *e)
{
	int rv;
	const RSA_METHOD *ossl_rsa_meth;
	const EC_KEY_METHOD *ossl_ec_meth;

	if (sdf_idx < 0) {
		sdf_idx = ENGINE_get_ex_new_index(0, NULL, NULL, NULL, 0);
		if (sdf_idx < 0) {
			goto end;
		}

		rsa_sdf_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
		ossl_rsa_meth = RSA_PKCS1_OpenSSL();
	}


	if (!(ctx = sdf_ctx_new())) {
		goto end;
	}

	ENGINE_set_ex_data(e, sdf_idx, sdf_ctx);


	if ((rv = SDF_OpenDevice(&hDeviceHandle)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_INIT, ESDF_R_OPEN_DEVICE_FAILURE);
		return 0;
	}


	rsa_sdf_idx = RSA_get_ex_new_index(0, NULL, NULL, NULL, 0);
	ossl_rsa_meth = RSA_PKCS1_OpenSSL();

	/*
	 * RSA_meth_set1_name
	 * RSA_meth_set_flags
	 * RSA_meth_set0_app_data
	 * RSA_meth_set_pub_enc/dec
	 * RSA_meth_set_priv_enc/dec
	 * RSA_meth_set_mod_exp
	 * RSA_meth_set_bn_mod_exp
	 * RSA_meth_set_init/finish
	 * RSA_meth_set_sign/verify
	 * RSA_meth_set_keygen
	 */
	if (!RSA_meth_set_pub_enc(sdf_rsa_method, sdf_rsa_pub_enc) ||
		!RSA_meth_set_pub_dec(sdf_rsa_method, sdf_rsa_pub_dec) ||
		!RSA_meth_set_priv_enc(sdf_rsa_method, sdf_rsa_priv_enc) ||
		!RSA_meth_set_priv_dec(sdf_rsa_method, sdf_rsa_priv_dec) ||
		!RSA_meth_set_mod_exp(sdf_rsa_method, RSA_meth_get_mod_exp(ossl_rsa_meth)) ||
		!RSA_meth_set_bn_mod_exp(sdf_rsa_method, RSA_meth_get_bn_mod_exp(ossl_rsa_meth)) ||
		!RSA_meth_set_finish(sdf_rsa_method, sdf_rsa_finish) ||
		!RSA_meth_set_sign(sdf_rsa_method, sdf_rsa_sign) ||
		!RSA_meth_set_verify(sdf_rsa_method, sdf_rsa_verify) ||
		!RSA_meth_set_keygen(sdf_rsa_method, sdf_rsa_keygen)) {
		goto end;
	}

	/*
	 * EC_KEY_METHOD_new
	 * EC_KEY_METHOD_free
	 * EC_KEY_METHOD_set_init
	 * EC_KEY_METHOD_set_keygen
	 * EC_KEY_METHOD_set_compute_key
	 * EC_KEY_METHOD_set_sign
	 * EC_KEY_METHOD_set_verify
	 * EC_KEY_METHOD_set_encrypt
	 * EC_KEY_METHOD_set_decrypt
	 */

	if (!EC_KEY_METHOD_set_init(sdf_ec_method,
			sdf_ec_init,
			sdf_ec_finish,
			sdf_ec_copy,
			sdf_ec_set_group,
			sdf_ec_set_private,
			sdf_ec_set_public) ||
		!EC_KEY_METHOD_set_keygen(sdf_ec_method,
			sdf_ec_keygen) ||
		!EC_KEY_METHOD_set_compute_key(sdf_ec_method,
			sdf_ec_ckey) ||
		!EC_KEY_METHOD_set_sign(sdf_ec_method,
			sdf_ec_sign,
			sdf_ec_sign_setup,
			sdf_ec_sign_sig) ||
		!EC_KEY_METHOD_set_verify(sdf_ec_method,
			sdf_ec_verify, sdf_ec_verify_sig) ||
		!EC_KEY_METHOD_set_encrypt(sdf_ec_method,
			sdf_ec_encrypt,
			sdf_ec_do_encrypt) ||
		!EC_KEY_METHOD_set_decrypt(sdf_ec_method,
			sdf_ec_decrypt,
			sdf_ec_do_decrypt)) {
		goto end;
	}

	return 1;
}

static int sdf_destory(ENGINE *e)
{
	RSA_meth_free(sdf_rsa_method);
	sdf_rsa_method = NULL;

	EC_KEY_METHOD_free(sdf_ec_method);
	sdf_ec_method = NULL;

	ERR_unload_ESDF_strings();
	return 1;
}

static int sdf_finish(ENGINE *e)
{
	SDF_CTX *ctx;
	ctx = ENGINE_get_ex_data(e, sdf_idx);
	sdf_ctx_free(ctx);
	ENGINE_set_ex_data(e, sdf_idx, NULL);

	int rv;
	if ((rv = SDF_CloseDevice(&hDeviceHandle)) != SDF_OK) {
		ESDFerr(ESDF_F_SDF_FINISH, ESDF_R_CLOSE_DEVICE_FAILURE);
		return 0;
	}
	return 1;
}

/*                          Load Public/Private Keys
 *
 * SDF devices have local storage for public and private keys. We assume that
 * the SDF devices use similar key storage model of SKF. The device has
 * multiple key containers, each container has at least two key pairs, the
 * signing key pair and the encryption/decryption key pair. Every key container
 * has a unique name or index. So when access a public key or a private key,
 * the caller should use both the container name/index and the key usage to
 * assign the key. Normally the key pairs in one container should be the same
 * type, RSA or EC/SM2. One container can not storage mixed key types.
 *
 * The following functions can be used to export public keys
 *	`SDF_ExportSignPublicKey_RSA`
 *	`SDF_ExportEncPublicKey_RSA`
 *	`SDF_ExportSignPublicKey_ECC`
 *	`SDF_ExportEncPublicKey_ECC`
 *
 * The callers should know the key types (for choosing functions), key index
 * (as function parameter) and key usage (for choosing function).
 *
 *
 * parse the `key_id` string can get the following info:
 *	key_type: rsa, ec, dsa ...
 *	key_usage: sign, encrypt
 *	id/label
 *
 * The SDF API supports the export of raw data of public keys in local storage,
 * while still provide functions of public key operations with local keys. For
 * SDF ENGINE, we have two strategies to implement public key operations: use
 * the exported public key and do it in the host with software, or use the key
 * index and SDF API to run it in the device. We use the second one because
 * many SDF devices are used as crypto accelerators. Users want to offload
 * public key operations to the device to reduce the CPU burden. So even for
 * exported public key `EVP_PKEY`, the key index and key usage are still kept.
 *
 *
 */

typedef struct {
	unsigned int uiKeyIndex;
	unsigned int uiKeyUsage;
} SDF_PKEY_DATA;

static EVP_PKEY *sdf_load_rsa_pubkey(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
{
}

static EVP_PKEY *sdf_load_pubkey(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
{
	EVP_PEKY *ret = NULL;
	EVP_PKEY *pkey = NULL;
	void *hSessionHandle = NULL;
	SDF_PKEY_DATA *data = NULL;
	int rv;

	if (!SDF_parse_key_id(key_id, &data->uiKeyType, &data->uiKeyUsage,
		&uiKeyIndex)) {
	}

	if (data->uiKeyType == SGD_PK_RSA) {

		if (uiKeyUsage = SGD_PK_SIGN) {
			if ((rv = SDF_ExportSignPublicKey_RSA(hSessionHandle,
				uiKeyIndex, &publicKey)) != SDR_OK) {
				ESDFerr(ESDF_F_SDF_LOAD_PUBKEY, 0);
				goto end;
			}
		} else if (uiKeyUsage == SGD_PK_ENC) {
			if ((rv = SDF_ExportEncPublicKey_RSA(hSessionHandle,
				uiKeyIndex, &publicKey)) != SDR_OK) {
				ESDFerr(ESDF_F_SDF_LOAD_PUBKEY, 0);
				goto end;
			}
		} else {
			OPENSSL_assert(0);
		}

		if (!(pkey = EVP_PKEY_new_from_RSArefPublicKey(&publicKey))) {
			ESDFerr(ESDF_F_SDF_LOAD_PUBKEY, ERR_R_GMAPI_LIB);
			goto end;
		}

	} else if (uiKeyType = SGD_PK_EC) {

		/* export key */
		if (uiKeyUsage == SGD_SM2_1) {
			if ((rv = SDF_ExportSignPublicKey_ECC(hSessionHandle,
				uiKeyIndex, &publicKey)) != SDR_OK) {
				ESDFerr(ESDF_F_SDF_LOAD_PUBKEY,
					ESDF_R_SDF_EXPORT_KEY_FAILURE);
				goto end;
			}
		} else {
			if ((rv = SDF_ExportEncPublicKey_ECC(hSessionHandle,
				uiKeyIndex, &publicKey)) != SDR_OK) {
				ESDFerr(ESDF_F_SDF_LOAD_PUBKEY,
					ESDF_R_SDF_EXPORT_KEY_FAILURE);
				goto end;
			}
		}

		/* set return value */
		if (!(pkey = EVP_PKEY_new_from_ECCrefPublicKey(&publicKey))) {
			ESDFerr(ESDF_F_SDF_LOAD_PUBKEY, ERR_R_GMAPI_LIB);
			goto end;
		}
	}
	ret = pkey;
	pkey = NULL;

end:
	EVP_PKEY_free(pkey);
	return ret;
}

/*
 *                              Load Private Keys
 *
 * When loading a private key, only the key index is assigned to the EVP_PKEY,
 * the raw key data is not provided.
 *
 * The SDF API does not support the export of private key raw data. Thus the
 * data exported are the key type, key index and key usage that the caller
 * already known. But typically loading a private key will be followed by using
 * the private key for signing or decryption, so the caller also need to get
 * the execution right of the private key. The SDF API exports the following
 * functions for private key access rights:
 *	`SDF_GetPrivateKeyAccessRight`
 *	`SDF_ReleasePrivateKeyAccessRight`
 * And password is used to access the rights. We use the `UI_METHOD` to let
 * uses input passwords.
 */
static EVP_PKEY *sdf_load_privkey(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
{

	unsigned char pucPassword[64];
	unsigned int uiPwdLength;


	if ((rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiKeyIndex,
		pucPassword, uiPwdLength)) != SDR_OK) {
	}





}


/*                              Certificates
 *
 * The SDF API provides a set of file operations to manipulate inner storage
 * of the crypto hardware. We assume that these storage can be used for the
 * storage of certificates.
 */

static int sdf_load_ssl_client_cert(ENGINE *e, SSL *ssl,
	STACK_OF(X509_NAME) *ca_dn, X509 **pcert,
	EVP_PKEY **pkey, STACK_OF(X509) **pother,
	UI_METHOD *ui_method, void *callback_data)
{

	unsigned char *fileName;
	unsigned int fileNameLen;


	*pcert = NULL;
	*pkey = NULL;

	/* `ca_dn` ==> fileName */

	if ((rv = SDF_ReadFile(
		hSessionHandle,
		fileName,
		fileNameLen,
		0,
		&uiReadLength,
		NULL)) != SDR_OK) {
		/* the SDF implementation does not support file
		 * or two-pass calling */

	}

	if (!(buf = OPENSSL_malloc(uiReadLength))) {
	}

	if ((rv = SDF_Readfile(
		hSessionHandle,
		fileName,
		fileNameLen,
		0,
		&uiReadLength,
		buf)) != SDR_OK) {
	}

	// parse the x509

	return 0;
}

static int skf_finish(ENGINE *e)
{
	ULONG rv;

	if (hDev) {
		if ((rv = SKF_DisConnectDev(hDev)) != SAR_OK) {
			ESKFerr(ESKF_F_SKF_FINISH, ESKF_R_SKF_DIS_CONNNECT_DEV_FAILED);
			return 0;
		}
	}

	if (session) {
		SDF_CloseSession(session);
	}
	if (device) {
		SDF_CloseDevice(device);
	}

	return 1;
}

void sdf_free_privkey(SDF_PIRVKEY *key)
{
	int rv;
	if (!key) {
		return;
	}
	if ((rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle,
		sdf_privkey->uiKeyIndex)) != SDR_OK) {
		//if some bad thing happens, we have to stop all the system
	}
	OPENSSL_free(key);
}


/*                             RSA_METHOD
 *
 */

static int sdf_rsa_init(RSA *rsa)
{
	// when happened?
	return 1;
}

static int sdf_rsa_finish(RSA *rsa)
{
	SDF_PRIVKEY *privkey;
	privkey = RSA_get_ex_data(rsa, rsa_sdf_idx);
	sdf_free_privkey(privkey);
	RSA_set_ex_data(rsa, rsa_sdf_idx, 0);
	return 1;
}

static int sdf_rsa_pub_enc(int inlen, const unsigned char *in,
	unsigned char *out, RSA *rsa, int padding)
{
	unsigned int uiKeyUsage = SGD_PK_ENC;
	unsigned int outlen;
	int rv;

	/* check `padding` */

	outlen = (unsigned int)inlen;
	if ((rv = SDF_InternalPublicKeyOperation_RSA(hSessionHandle,
		uiKeyIndex, uiKeyUsage, (unsigned char *)in,
		(unsigned int)inlen, out, &outlen)) != SDR_OK) {
	}
	if (outlen != (unsigned int)inlen) {
	}

	return 1;
}

static int sdf_rsa_pub_dec(int inlen, const unsigned char *in,
	unsigned char *out, RSA *rsa, int padding)
{
	unsigned int uiKeyUsage = SGD_PK_SIGN;
	unsigned int outlen;
	int rv;

	outlen = (unsigned int)inlen;
	if ((rv = SDF_InternalPublicKeyOperation_RSA(hSessionHandle,
		uiKeyIndex, uiKeyUsage, (unsigned char *)in,
		(unsigned int)inlen, out, &outlen)) != SDR_OK) {
	}
	if (outlen != (unsigned int)inlen) {
	}

	return 1;
}

static int sdf_rsa_priv_enc(int inlen, const unsigned char *in,
	unsigned char *out, RSA *rsa, int padding)
{
	unsigned int uiKeyUsage = SGD_PK_SIGN;
	unsigned int outlen;
	int rv;

	outlen = (unsigned int)inlen;
	if ((rv = SDF_InternalPrivateKeyOperation_RSA(hSessionHandle,
		uiKeyIndex, uiKeyUsage, (unsigned char *)in,
		(unsigned int)inlen, out, &outlen)) != SDR_OK) {
	}
	if (outlen != (unsigned int)inlen) {
	}

	return 1;
}

static int sdf_rsa_priv_dec(int inlen, const unsigned char *in,
	unsigned char *out, RSA *rsa, int padding)
{
	unsigned int uiKeyUsage = SGD_PK_ENC;
	unsigned int outlen;
	int rv;

	outlen = (unsigned int)inlen;
	if ((rv = SDF_InternalPrivateKeyOperation_RSA(hSessionHandle,
		uiKeyIndex, uiKeyUsage, (unsigned char *)in,
		(unsigned int)inlen, out, &outlen)) != SDR_OK) {
	}
	if (outlen != (unsigned int)inlen) {
	}

	return 1;
}

static int sdf_rsa_sign(int type, const unsigned char *dgst,
	unsigned int dgstlen, unsigned char *sig, unsigned int *siglen,
	const RSA *rsa)
{
	return 0;
}

static int sdf_rsa_verify(int type, const unsigned char *dgst,
	unsigned int dgstlen, const unsigned char *sig, unsigned int siglen,
	const RSA *rsa)
{
	return 0;
}

static int sdf_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	int ret = 0;
	RSArefPublicKey publicKey;
	RSArefPrivateKey privateKey;
	int rv;

	if (e != NULL || cb != NULL) {
		/* we can show some alerts to callers */
	}

	if ((rv = SDF_GenerateKeyPair_RSA(hSessionHandle, (unsigned int)bits,
		&publicKey, &privateKey)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_RSA_KEYGEN, ESDF_R_SDF_FAILURE);
		goto end;
	}

	if (!RSA_set_RSArefPrivateKey(rsa, &privateKey)) {
		ESDFerr(ESDF_F_SDF_RSA_KEYGEN, ERR_R_GMAPI_LIB);
		goto end;
	}

	ret = 1;
end:
	OPENSSL_cleanse(&privateKey, sizeof(privateKey));
	return ret;
}

/*
 *                            EC_KEY_METHOD
 *************************************************************************
 * The elliptic curve keys in the secondary storage can be referenced by the
 * key indexes through the SDF API. The SDF API does not support key pair
 * generation functions working on its key storage. We assume that the vendors
 * might provides some admin channels for generation or importing key pairs
 * into the secondary key storage. The SDF API neither provides any function to
 * enumerate the key pairs in the key storage. So the caller has to know the
 * index of the key to be used, and the password to access this key. One
 * possible solution to enumerate the keys is to try every possible key index
 * number (maybe start from 0) with the `SDF_GetPrivateKeyAccessRight`, and use
 * the `SDF_ExportSignPublicKey_RSA`, `SDF_ExportEncPublicKey_RSA`,
 * `SDF_ExportSignPublicKey_ECC` and `SDF_ExportEncPublicKey_ECC` to export the
 * public key.
 *
 * The SDF ENGINE provides a command for setting the key indexes: RSA
 * encryption key, RSA signing key, EC encryption key, EC signing key and ECDH
 * key. The corresponding password is also required.
 */



/*
 * EC_KEY support ex_data,
 */
static int ec_sdf_idx = -1;


static int sdf_ec_sign()
{
}

static int sdf_sm2_decrypt()
{
}


static int sdf_ec_init(EC_KEY *ec_key)

static int sdf_ec_finish(EC_KEY *ec_key)
static int sdf_ec_copy(EC_KEY *dest, const EC_KEY *src)

static int sdf_ec_set_group(EC_KEY *key, const EC_GROUP *group)

static int sdf_ec_set_private(EC_KEY *key, const BIGNUM *priv_key)

static int sdf_ec_set_public(EC_KEY *key, const EC_POINT *pub_key)

static int sdf_ec_keygen(EC_KEY *ec_key)

static int sdf_ec_sign(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen,
	const BIGNUM *kinv, const BIGNUM *r, EC_KEY *ec_key)
{
	ECDSA_SIG *sig = NULL;

	if (!(sig = sdf_ec_sign_sig(dgst, dgstlen, kinv, r, ec_key))) {
	}

	// i2d_ECDSA_SIG
}

static ECDSA_SIG *sdf_ec_sign_sig(const unsigned char *dgst, int dgstlen,
	const BIGNUM *kinv, const BIGNUM *r, EC_KEY *ec_key)
{
	ECDSA_SIG *ret;
	ECCSignature sigblob;
	unsigned int uiKeyIndex;

	if (!hDeviceHandle) {
		ESDFerr(ESDF_F_SDF_EC_SIGN_SIG, ESDF_R_DEVICE_NOT_OPENED);
		return NULL;
	}
	if (!hSessionHandle) {
		ESDFerr(ESDF_F_SDF_EC_SIGN_SIG, ESDF_R_SESSION_NOT_OPENED);
		return NULL;
	}

	/* get uiKeyIndex from ec_key */

	if ((rv = SDF_InternalSign_ECC(hSessionHandle, uiKeyIndex,
		dgst, (unsigned int)dgstlen, &sigblob)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_EC_SIGN_SIG, ESDF_R_SDF_FAILURE);
		return NULL;
	}

	if (!(ret = ECDSA_SIG_new_from_ECCSignature(&sigblob))) {
		ESDFerr(ESDF_F_SDF_EC_SIGN_SIG, ERR_R_GMAPI_LIB);
		return NULL;
	}

	return ret;
}

static int sdf_ec_verify(int type, const unsigned char *dgst, int dgstlen,
	const unsigned char *sig, int siglen, EC_KEY *ec_key)
{
	int ret = -1;
	ECCSignature signature;
	int rv;

	if (!hDeviceHandle || !hSessionHandle) {
		ESDFerr(ESDF_F_SDF_EC_VERIFY, ESDF_R_NOT_INITIALIZED);
		return -1;
	}

	if ((rv = SDF_InternalVerify_ECC(hSessionHandle, uiKeyIndex,
		dgst, (unsigned int)dgstlen, &signature)) != SDR_OK) {

		if (rv == SDR_VERIFYERR) {
			ret = 0;
		}
	}



}

static int sdf_ec_verify_sig(const unsigned char *dgst, int dgstlen,
	const ECDSA_SIG *sig, EC_KEY *ec_key)
{
	ECCSignature signature;
	int rv;

	if ((rv = ECDSA_SIG_get_ECCSignature(sig, &signature) != SDR_OK)) {
		ESDFerr(ESDF_F_SDF_EC_VERIFY_SIG, ERR_R_GMAPI_LIB);
		return -1;
	}
	if ((rv = SDF_InternalVerify_ECC(hSessionHandle, uiKeyIndex,
		dgst, (unsigned int)dgstlen, &signature)) != SDR_OK) {
		ESDFerr(ESDF_F_SDF_EC_VERIFY_SIG, ESDF_R_SDF_LIB);
		if (rv == SDR_VERIFYERR) {
			return 0;
		} else {
			return -1;
		}
	}

	return 1;
}

static int sdf_ec_encrypt()
{
}

static  int sdf_ec_do_encrypt()
{
}

static int sdf_ec_decrypt()
{
}

static int sdf_ec_do_decrypt()
{
}



/* ============================= ENGINE ================================== */


static int bind_sdf(ENGINE *e)
{
	int ret = 0;

	sdf_rsa_method = RSA_meth_new("GmSSL SDF RSA method", 0);
	sdf_ec_method = EC_KEY_METHOD_new("GmSSL SDF EC method", 0);
	if (!sdf_rsa_method || !sdf_ec_method) {
		goto end;
	}

	/*
	 * ENGINE_set_id/name
	 * ENGINE_set_destroy/init/finish/ctrl_function
	 * ENGINE_set_flags
	 * ENGINE_set_cmd_defns
	 * ENGINE_set_RSA/DSA/EC/DH
	 * ENGINE_set_RAND
	 * ENGINE_set_load_privkey/pubkey_function
	 * ENGINE_set_load_ssl_client_cert_function
	 * ENGINE_set_ciphers/digests
	 * ENGINE_set_pkey_meths
	 * ENGINE_set_pkey_asn1_meths
	 */

	if (!ENGINE_set_id(e, engine_sdf_id) ||
		!ENGINE_set_name(e, engine_sdf_name) ||
		!ENGINE_set_flags(e, ENGINE_FLAGS_NO_REGISTER_ALL) ||
		!ENGINE_set_init_function(e, sdf_init) ||
		!ENGINE_set_finish_function(e, sdf_finish) ||
		!ENGINE_set_destroy_function(e, sdf_destroy) ||
		!ENGINE_set_cmd_defns(e, sdf_cmd_defns) ||
		!ENGINE_set_ctrl_function(e, sdf_ctrl) ||
		!ENGINE_set_RAND(e, &sdf_rand) ||
		!ENGINE_set_digests(e, sdf_digests) ||
		!ENGINE_set_ciphers(e, sdf_ciphers) ||
		!ENGINE_set_RSA(e, sdf_rsa_method) ||
		!ENGINE_set_EC(e, sdf_ec_method) ||
		!ENGINE_set_load_privkey_function(e, sdf_load_privkey) ||
		!ENGINE_set_load_pubkey_function(e, sdf_load_pubkey) ||
		!ENGIEN_set_load_ssl_client_cert_function(e, sdf_load_cert)) {
		return 0;
	}

	ret = 1;
end:
	if (!ret) {
		RSA_meth_free(sdf_rsa_method);
		sdf_rsa_method = NULL;
		EC_KEY_METHOD_free(sdf_ec_method);
		sdf_ec_method = NULL;
	}
	return ret;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
	if (id && strcmp(id, engine_sdf_id) != 0) {
		return 0;
	}
	if (!bind_sdf(e)) {
		return 0;
	}
	return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#else
static ENGINE *engine_sdf(void)
{
	ENGINE *ret = ENGINE_new();
	if (ret == NULL)
		return NULL;
	if (!bind_sdf(ret)) {
		ENGINE_free(ret);
		return NULL;
	}
	return ret;
}

void engine_load_sdf_int(void)
{
	ENGINE *toadd = engine_sdf();
	if (!toadd)
		return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
}

#endif /* OPENSSL_NO_DYNAMIC_ENGINE */
