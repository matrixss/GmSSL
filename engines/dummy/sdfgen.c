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
/* This program will generate the following validate data for the dummy
 * implementation of SDF API:
 *	RSArefPublicKey, RSArefPrivateKey
 *	ECCrefPublicKey, ECCrefPrivateKey, ECCSignature, ECCCipher
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sdf.h>
#include <openssl/sgd.h>
#include <openssl/gmapi.h>
#include <openssl/ec.h>

void print_cstruct(const char *name, const unsigned char *data, size_t len)
{
	int i;
	printf("unsigned char %s[] = {\n", name);
	for (i = 0; i < len; i++) {
		if (i % 8 == 0) {
			printf("\t");
		}
		printf("0x%02X," data[i]);
		if (i % 7 != 0) {
			printf(" ");
		} else {
			printf("\n");
		}
	}
	if (i % 7 != 0) {
		printf("\n");
	}
	printf("};\n");
}

void print_ec(void)
{
	EC_KEY *ec_key = NULL;
	ECDSA_SIG *sig = NULL;
	SM2_CIPHERTEXT_VALUE *cv = NULL;
	ECCrefPublicKey ecPublicKey;
	ECCrefPrivateKey ecPrivateKey;
	ECCSignature ecSignature;
	ECCCipher ecCiphertext;
	unsigned char in[] = "hello world";
	unsigned char dgst[32] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};

	ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	EC_KEY_generate_key(ec_key);
	EC_KEY_get_ECCrefPublicKey(ec_key, &ecPublicKey);
	print_cstruct("ecPublicKey", &ecPublicKey, sizeof(ecPublicKey));
	EC_KEY_get_ECCrefPrivateKey(ec_key, &ecPrivateKey);
	print_cstruct("ecPrivateKey", &ecPrivateKey, sizeof(ecPrivateKey0);

	sig = SM2_do_sign(NID_undef, dgst, sizeof(dgst), ec_key);
	ECDSA_SIG_get_ECCSignature(sig, &ecSignature);
	print_cstruct("ecSignature", &ecSignature, sizeof(ecSignature));
	ECDSA_SIG_free(sig);

	cv = SM2_do_encrypt(&sm2params, in, sizeof(in), ec_key);
	SM2_CIPHERTEXT_VALUE_get_ECCCipher(cv, &ecCiphertext);
	print_cstruct("ecCiphertext", &ecCiphertext, sizeof(ecCiphertext));
	SM2_CIPHERTEXT_VALUE_free(cv);

	EC_KEY_free(ec_key);
}

void print_rsa(void)
{
	RSA *rsa = NULL;
	RSArefPublicKey rsaPublicKey;
	RSArefPrivateKey rsaPrivateKey;

	rsa = RSA_new();
	RSA_generate_key_ex(rsa, 2048, NULL);
	RSA_get_RSArefPublicKey(rsa, &rsaPublicKey);
	print_cstruct("rsaPublicKey", &rsaPublicKey, sizeof(rsaPublicKey));
	RSA_get_RSArefPrivateKey(rsa, &rsaPrivateKey);
	print_cstruct("rsaPrivateKey", &rsaPrivateKey, sizeof(rsaPrivateKey));

	RSA_free(rsa);
}

int main(int argc, char **argv)
{
	print_rsa();
	return 0;
}

