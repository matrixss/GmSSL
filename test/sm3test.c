/* ====================================================================
 * Copyright (c) 2014 - 2016 The GmSSL Project.  All rights reserved.
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
#include "../e_os.h"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sm3.h>

static char *testhex[] = {
	/* 0 "abc" */
	"616263",
	/* 1 "abcd" 16 times */
	"6162636461626364616263646162636461626364616263646162636461626364"
	"6162636461626364616263646162636461626364616263646162636461626364",
	/* 2 p.57 ZA */
	"0090"
	"414C494345313233405941484F4F2E434F4D"
	"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
	"63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
	"421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
	"0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
	"0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A"
	"7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857",
	/* 3 p.59 ZA */
	"0090"
	"414C494345313233405941484F4F2E434F4D"
	"000000000000000000000000000000000000000000000000000000000000000000"
	"00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B"
	"00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD"
	"013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E"
	"0165961645281A8626607B917F657D7E9382F1EA5CD931F40F6627F357542653B2"
	"01686522130D590FB8DE635D8FCA715CC6BF3D05BEF3F75DA5D543454448166612",
	/* 4 p.72 ZA */
	"0090"
	"414C494345313233405941484F4F2E434F4D"
	"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
	"63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
	"421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
	"0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
	"3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE1655"
	"3DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B",
	/* 5 p.72 ZB */
	"0088"
	"42494C4C343536405941484F4F2E434F4D"
	"787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
	"63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
	"421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
	"0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
	"245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F43"
	"53C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C",
	/* 6 p.75 ZA */
	"0090"
	"414C494345313233405941484F4F2E434F4D"
	"000000000000000000000000000000000000000000000000000000000000000000"
	"00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B"
	"00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD"
	"013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E"
	"008E3BDB2E11F9193388F1F901CCC857BF49CFC065FB38B9069CAAE6D5AFC3592F"
	"004555122AAC0075F42E0A8BBD2C0665C789120DF19D77B4E3EE4712F598040415",
	/* 7 p.76 ZB */
	"0088"
	"42494C4C343536405941484F4F2E434F4D"
	"000000000000000000000000000000000000000000000000000000000000000000"
	"00E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B"
	"00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD"
	"013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E"
	"0034297DD83AB14D5B393B6712F32B2F2E938D4690B095424B89DA880C52D4A7D9"
	"0199BBF11AC95A0EA34BBD00CA50B93EC24ACB68335D20BA5DCFE3B33BDBD2B62D",
};

static char *dgsthex[] = {
	"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
	"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
	"F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A",
	"26352AF82EC19F207BBC6F9474E11E90CE0F7DDACE03B27F801817E897A81FD5",
	"E4D1D0C3CA4C7F11BC8FF8CB3F4C02A78F108FA098E51A668487240F75E20F31",
	"6B4B6D0E276691BD4A11BF72F4FB501AE309FDACB72FA6CC336E6656119ABD67",
	"ECF0080215977B2E5D6D61B98A99442F03E8803DC39E349F8DCA5621A9ACDF2B",
	"557BAD30E183559AEEC3B2256E1C7C11F870D22B165D015ACF9465B09B87B527",
};

int sm3evptest(void)
{
	int ret = 0;
	unsigned char *testbuf = NULL;
	unsigned char *dgstbuf = NULL;
	long testbuflen, dgstbuflen;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	int i;

	for (i = 0; i < sizeof(testhex)/sizeof(testhex[0]); i++) {
		if (!(testbuf = OPENSSL_hexstr2buf(testhex[i], &testbuflen))) {
			goto end;
		}
		if (!(dgstbuf = OPENSSL_hexstr2buf(dgsthex[i], &dgstbuflen))) {
			goto end;
		}

		dgstlen = sizeof(dgst);
		if (!EVP_Digest(testbuf, testbuflen, dgst, &dgstlen, EVP_sm3(), NULL)) {
			return 0;
		}
		if (memcmp(dgstbuf, dgst, dgstlen) == 0) {
			printf("test %d passed\n", i+1);
		} else {
			printf("test %d failed\n", i+1);
		}

		OPENSSL_free(testbuf);
		OPENSSL_free(dgstbuf);
		testbuf = NULL;
		dgstbuf = NULL;
	}

	ret = 1;

end:
	OPENSSL_free(testbuf);
	OPENSSL_free(dgstbuf);
	return ret;
}
/*
int test0(int argc, char **argv)
{
	int i;
	int j;
	unsigned char buf[2024];
	size_t len = sizeof(buf);
	unsigned char dgst[32];

	for (i = 0; i < sizeof(test)/sizeof(test[0]); i++) {
		len = sizeof(buf);
		hex2buf(test[i], buf, &len);
		sm3(buf, len, dgst);
		len = sizeof(buf);
		hex2buf(ret[i], buf, &len);
		if (memcmp(dgst, buf, len)) {
			printf("test %d failed\n", i+1);
			printf("error: SM3(%s) != %s\n", test[i], ret[i]);
		} else {
			printf("test %d ok\n", i+1);
		}
	}

	for (i = 0; i < sizeof(test)/sizeof(test[0]); i++) {
		unsigned char mac[SM3_DIGEST_LENGTH];
		unsigned int maclen;
		unsigned char key[SM3_BLOCK_SIZE * 2];
		size_t keylen = (sizeof(key)/(sizeof(test)/sizeof(test[0]))) * (i+1);
		len = sizeof(buf);
		hex2buf(test[i], buf, &len);
		RAND_pseudo_bytes(key, keylen);
		sm3_hmac(buf, len, key, keylen, dgst);
		HMAC(EVP_sm3(), key, keylen, buf, len, mac, &maclen);
		if (memcmp(dgst, mac, maclen)) {
			printf("test %lu failed\n", sizeof(test)/sizeof(test[0]) + 1 + i);
		} else {
			printf("test %lu ok\n", sizeof(test)/sizeof(test[0]) + 1 + i);
		}
	}

end:
	return 0;
}
*/

int main(int argc, char **argv)
{
	sm3evptest();
	return 0;
}
