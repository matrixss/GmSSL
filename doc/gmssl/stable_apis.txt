
 STABLE APIS
 ===========

 As the GmSSL project is still in aggressively developing, APIs might be
 changed during major updates. For developers who want to integrate GmSSL into
 your project and continuely update with the new version of GmSSL, you can
 choose the stable APIs.

 Although the header files exposed many functions and data structures, only a
 few of the functions, i.e. the stable APIs will not be changed during udpates.

 Here are some of the stable APIs:

 1. EVP API (include/openssl/evp.h)
 2. GM APIs (include/openssl/sgd.h,saf.h,sdf.h,skf.h)




include/openssl/sm2.h
	SM2_compute_id_digest
	SM2_encrypt_with_recommended
	SM2_decrypt_with_recommended
	SM2_sign
	SM2_verify

include/openssl/ecies.h

 ECIES_encrypt_with_recommended
 ECIES_decrypt_with_recommended

include/openssl/bfibe.h

 BFIBE_extract_private_key
 BFIBE_encrypt
 BFIBE_decrypt

include/openssl/bb1ibe.h

 BB1IBE_extract_private_key
 BB1IBE_encrypt
 BB1IBE_decrypt

include/openssl/sm9.h
	SM9_sign
	SM9_verify
	SM9_encrypt
	SM9_decrypt



