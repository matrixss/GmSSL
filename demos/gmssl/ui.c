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
#include <openssl/ui.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
	UI *ui = NULL;
	const UI_METHOD *ui_method = UI_OpenSSL();
	char name[64];
	char password[64];
	char password2[64];
	char boolval[64];

	if (!(ui = UI_new_method(ui_method))) {
		goto end;
	}

	/*
	if (UI_add_input_string(ui, "Name", 0, name, 1, sizeof(name) - 1) < 0) {
		goto end;
	}

	if (UI_add_verify_string(ui, "Password", 0,
		password, 1, sizeof(password)-1, password2) < 0) {
		goto end;
	}
	*/

	if (UI_add_input_boolean(ui, "Yes or No", 0, "YyOo", "NnCc", 0,
		boolval) < 0) {
		goto end;
	}
	/*
	if (UI_add_info_string(ui, "Warning") < 0) {
		goto end;
	}
	*/

	if (UI_process(ui) < 0) {
		goto end;
	}
	//printf("name = %s\n", UI_get0_result(ui, 0));

	/*
	if (UI_add_error_string(ui, "Error") < 0) {
		goto end;
	}
	UI_process(ui);
	*/

//	printf("password = %s\n", UI_get0_result(ui, 1));
	printf("Y/N = %s\n", UI_get0_result(ui, 0));

end:
	UI_free(ui);
	return 0;
}
