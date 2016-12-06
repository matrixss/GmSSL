/* ====================================================================
 * Copyright (c) 2015 - 2016 The GmSSL Project.  All rights reserved.
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
/*
 * Common routines for all GM APIs (SAF, SDF, SKF)
 */

#ifndef HEADER_GMAPI_H
#define HEADER_GMAPI_H

#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/sgd.h>
#include <openssl/saf.h>
#include <openssl/sdf.h>
#include <openssl/skf.h>


#ifdef __cplusplus
extern "C" {
#endif

/* SGD <==> EVP */
const EVP_MD *EVP_get_digestbysgd(int sgd);
const EVP_CIPHER *EVP_get_cipherbysgd(int sgd);

/* SDF types <==> Native types */
RSA *RSA_new_from_RSArefPublicKey(const RSArefPublicKey *ref);
RSA *RSA_new_from_RSArefPrivateKey(const RSArefPrivateKey *ref);
int RSA_set_RSArefPublicKey(RSA *rsa, const RSArefPublicKey *ref);
int RSA_set_RSArefPrivateKey(RSA *rsa, const RSArefPrivateKey *ref);
int RSA_get_RSArefPublicKey(RSA *rsa, RSArefPublicKey *ref);
int RSA_get_RSArefPrivateKey(RSA *rsa, RSArefPrivateKey *ref);
EC_KEY *EC_KEY_new_from_ECCrefPublicKey(const ECCrefPublicKey *ref);
EC_KEY *EC_KEY_new_from_ECCrefPrivateKey(const ECCrefPrivateKey *ref);
int EC_KEY_set_ECCrefPublicKey(EC_KEY *ec_key, const ECCrefPublicKey *ref);
int EC_KEY_set_ECCrefPrivateKey(EC_KEY *ec_key, const ECCrefPrivateKey *ref);
int EC_KEY_get_ECCrefPublicKey(EC_KEY *ec_key, ECCrefPublicKey *ref);
int EC_KEY_get_ECCrefPrivateKey(EC_KEY *ec_key, ECCrefPrivateKey *ref);
SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_new_from_ECCCipher(const ECCCipher *ref);
int SM2_CIPHERTEXT_VALUE_set_ECCCipher(SM2_CIPHERTEXT_VALUE *cv, const ECCCipher *ref);
int SM2_CIPHERTEXT_VALUE_get_ECCCipher(const SM2_CIPHERTEXT_VALUE *cv, ECCCipher *ref);
ECDSA_SIG *ECDSA_SIG_new_from_ECCSignature(const ECCSignature *ref);
int ECDSA_SIG_set_ECCSignature(ECDSA_SIG *sig, const ECCSignature *ref);
int ECDSA_SIG_get_ECCSignature(const ECDSA_SIG *sig, ECCSignature *ref);

/* SKF types <==> Native types */
RSA *RSA_new_from_RSAPUBLICKEYBLOB(const RSAPUBLICKEYBLOB *blob);
RSA *RSA_new_from_RSAPRIVATEKEYBLOB(const RSAPRIVATEKEYBLOB *blob);
int RSA_set_RSAPUBLICKEYBLOB(RSA *rsa, const RSAPUBLICKEYBLOB *blob);
int RSA_set_RSAPRIVATEKEYBLOB(RSA *rsa, const RSAPRIVATEKEYBLOB *blob);
int RSA_get_RSAPUBLICKEYBLOB(RSA *rsa, RSAPUBLICKEYBLOB *blob);
int RSA_get_RSAPRIVATEKEYBLOB(RSA *rsa, RSAPRIVATEKEYBLOB *blob);
EC_KEY *EC_KEY_new_from_ECCPUBLICKEYBLOB(const ECCPUBLICKEYBLOB *blob);
EC_KEY *EC_KEY_new_from_ECCPRIVATEKEYBLOB(const ECCPRIVATEKEYBLOB *blob);
int EC_KEY_set_ECCPUBLICKEYBLOB(EC_KEY *ec_key, const ECCPUBLICKEYBLOB *blob);
int EC_KEY_get_ECCPUBLICKEYBLOB(EC_KEY *ec_key, ECCPUBLICKEYBLOB *blob);
int EC_KEY_set_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, const ECCPRIVATEKEYBLOB *blob);
int EC_KEY_get_ECCPRIVATEKEYBLOB(EC_KEY *ec_key, ECCPRIVATEKEYBLOB *blob);
SM2_CIPHERTEXT_VALUE *SM2_CIPHERTEXT_VALUE_new_from_ECCCIPHERBLOB(const ECCCIPHERBLOB *blob);
int SM2_CIPHERTEXT_VALUE_set_ECCCIPHERBLOB(SM2_CIPHERTEXT_VALUE *cv, const ECCCIPHERBLOB *blob);
int SM2_CIPHERTEXT_VALUE_get_ECCCIPHERBLOB(const SM2_CIPHERTEXT_VALUE *cv, ECCCIPHERBLOB *blob);
ECDSA_SIG *ECDSA_SIG_new_from_ECCSIGNATUREBLOB(const ECCSIGNATUREBLOB *blob);
int ECDSA_SIG_get_ECCSIGNATUREBLOB(const ECDSA_SIG *sig, ECCSIGNATUREBLOB *blob);
int ECDSA_SIG_set_ECCSIGNATUREBLOB(ECDSA_SIG *sig, const ECCSIGNATUREBLOB *blob);


/* BEGIN ERROR CODES */
