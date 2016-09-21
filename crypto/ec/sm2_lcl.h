
#define SM2_MAX_ID_BITS				65535
#define SM2_MAX_ID_LENGTH			(SM2_MAX_ID_BITS/8)
#define SM2_DEFAULT_ID				"anonym@gmssl.org"
#endif
#define SM2_DEFAULT_ID_DIGEST_MD		EVP_sm3()
#define SM2_ID_DIGEST_LENGTH			SM3_DIGEST_LENGTH
#define SM2_DEFAULT_POINT_CONVERSION_FORM	POINT_CONVERSION_UNCOMPRESSED
#define SM2_MAX_FIELD_BYTES			((OPENSSL_ECC_MAX_FIELD_BITS + 7)/8)

ECIESCiphertext *SM2_do_encrypt(int type,
                                const unsigned char *in, size_t inlen,
                                EC_KEY *ec_key);
int SM2_do_decrypt(int type, const ECIESCiphertext *in,
                   unsigned char *out, size_t *outlen,
                   EC_KEY *ec_key);

typedef struct sm2_enc_params_st {
	const EVP_MD *kdf_md;
	const EVP_MD *mac_md;
	int mactag_size;
	point_conversion_form_t point_form;
} SM2_ENC_PARAMS;
typedef struct sm2_kap_ctx_st {

	const EVP_MD *id_dgst_md;
	const EVP_MD *kdf_md;
	const EVP_MD *checksum_md;
	point_conversion_form_t point_form;
	KDF_FUNC kdf;

	int is_initiator;
	int do_checksum;

	EC_KEY *ec_key;
	unsigned char id_dgst[EVP_MAX_MD_SIZE];
	unsigned int id_dgstlen;

	EC_KEY *remote_pubkey;
	unsigned char remote_id_dgst[EVP_MAX_MD_SIZE];
	unsigned int remote_id_dgstlen;

	const EC_GROUP *group;
	BN_CTX *bn_ctx;
	BIGNUM *order;
	BIGNUM *two_pow_w;

	BIGNUM *t;
	EC_POINT *point;
	unsigned char pt_buf[1 + (OPENSSL_ECC_MAX_FIELD_BITS+7)/4];
	unsigned char checksum[EVP_MAX_MD_SIZE];

} SM2_KAP_CTX;
