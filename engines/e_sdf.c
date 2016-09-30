/* engines/e_sdf.c */
/* ====================================================================
 * Copyright (c) 2015-2016 The GmSSL Project.  All rights reserved.
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
 *
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
#include "e_sdf_err.c"
#include "../crypto/ecdsa/ecs_locl.h"


static void *device_handle = NULL;
static void *session_handle = NULL;
static int key_index = -1;


#define SKF_CMD_SO_PATH			ENGINE_CMD_BASE
#define SKF_CMD_OPEN_DEV		(ENGINE_CMD_BASE + 1)
#define SKF_CMD_DEV_AUTH		(ENGINE_CMD_BASE + 2)

static const ENGINE_CMD_DEFN skf_cmd_defns[] = {
	{SDF_CMD_SO_PATH,
	 "SO_PATH",
	 "Specifies the path to the vendor's SKF shared library",
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

static int open_dev(void)
{
	int r;
	void *dev_handle = NULL;

	if ((r = SDF_OpenDevice(&dev_handle)) != SDR_OK) {
		ESDFerr();
		return 0;
	}
	if ((r = SDF_OpenSession(&session_handle)) != SDR_OK) {
		ESDFerr();
		return 0;
	}

	return 1;
}

static int skf_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
{
	switch (cmd) {
	case SKF_CMD_OPEN_DEV:
		return open_dev(p);
	case SKF_CMD_DEV_AUTH:
		return dev_auth(p);
	case SKF_CMD_OPEN_APP:
		return open_app(p);
	case SKF_CMD_VERIFY_PIN:
		return verify_pin(p);
	case SKF_CMD_OPEN_CONTAINER:
		return open_container(p);
	}

	ESKFerr(ESKF_F_SKF_ENGINE_CTRL, ESKF_R_INVALID_CTRL_CMD);
	return 0;
}

static EVP_PKEY *sdf_load_pubkey(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data)
{
	int r;
	EVP_PKEY *ret = NULL;
	ECCrefPublicKey pubkey;


	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BN_CTX *bn_ctx = NULL;



	memset(&pubkey, 0, sizeof(pubkey));
	if ((r = SDF_ExportSignPublicKey_ECC(session_handle, key_index,
		&pubkey)) != SDR_OK) {
		return 0;
	}

	/* convert pubkey to EVP_PKEY */

	ret = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	x = BN_bin2bn(ref->x, 256/8, NULL);
	y = BN_bin2bn(ref->y, 256/8, NULL);
	bn_ctx = BN_new();
	if (!ret || !x || !y || !bn_ctx) {
		goto end;
	}

	if (!EC_PKEY_set_public_key_affine_coordinates(ec_key, x, y, bn_ctx)) {
		goto end;
	}

	/* set evp_pkey */


	return ret;
}

static int skf_init(ENGINE *e)
{
	return 1;
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

/* set the default sm2 */
static ECDSA_METHOD skf_sm2sign = {
	"SDF SM2 Signing Method",
	NULL,
	NULL,
	NULL,
	0,
	NULL,
};

static ECDSA_SIG *sdf_sm2_do_sign(const unsigned char *dgst, int dgstlen,
	const BIGNUM *a, const BIGNUM *b, EC_KEY *ec_key)
{
	ECDSA_SIG *ret = NULL;

	ECCSignature sigbuf;
	ECCSignature *sig = &sigbuf;
	BYTE *pbDigest = (BYTE *)dgst;
	ULONG ulDigestLen = (ULONG)dgstlen;
	ULONG rv;
	int ok = 0;


	if ((r = SDF_InternalSign_ECC(session, key_index, dgst, dgstlen,
		&sigbuf)) != SDR_OK) {
		return -1;
	}


	if (!(ret = ECDSA_SIG_new())) {
		goto end;
	}
	if (!(ret->r = BN_bin2bn(sig->r, 256/8, ret->r))) {
		goto end;
	}
	if (!(ret->s = BN_bin2bn(sig->s, 256/8, ret->s))) {
		goto end;
	}

	ok = 1;
end:
	if (!ok && ret) {
		ECDSA_SIG_free(ret);
		ret = NULL;
	}

	return ret;
}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_skf(void)
{
	ENGINE *ret = ENGINE_new();
	if (!ret) {
		return NULL;
	}

	if (!bind_helper(ret)) {
		ENGINE_free(ret);
		return NULL;
	}


	return ret;
}

void ENGINE_load_skf(void)
{
	ENGINE *e_skf = engine_skf();
	if (!e_skf) {
		return;
	}

	ENGINE_add(e_skf);
	ENGINE_free(e_skf);
	ERR_clear_error();
}
#endif

static const char *engine_skf_id = "SKF";
static const char *engine_skf_name = "SKF API Hardware Engine";

static int bind(ENGINE *e, const char *id)
{
	if (id && strcmp(id, engine_skf_id)) {
		return 0;
	}

	if (!ENGINE_set_id(e, engine_skf_id) ||
		!ENGINE_set_name(e, engine_sdf_name) ||
		!ENGINE_set_init_function(e, sdf_init) ||
		!ENGINE_set_finish_function(e, sdf_finish) ||
		!ENGINE_set_ctrl_function(e, sdf_engine_ctrl) ||
		!ENGINE_set_destroy_function(e, sdf_sm2_do_sign) ||
		!ENGINE_set_load_pubkey_function(e, sdf_load_pubkey) ||
		!ENGINE_set_ECDSA(e, NULL)) {

		return 0;
	}

	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind);
IMPLEMENT_DYNAMIC_CHECK_FN();
