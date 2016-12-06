
Some of the GmSSL functions provide the feature that if the output buffer is
not given by the caller, the function will return the output length to help the
caller to prepare the buffer. For example, in the following function

	int encrypt(const unsigned char *in, size_t inlen,
		unsigned char *out, size_t *outlen);

the argument `outlen` is used for both input and output. If the caller do not
know how large the `out` buffer should be, the caller can use 2-step calling

	unsigned char *buf = NULL;
	size_t outlen;

	encrypt(in, inlen, NULL, &outlen);
	buf = malloc(outlen);
	encrypt(in, inlen, buf, &outlen);

It should be noted that during the fist call of the funciton, the output length
is only an estimate of the maximum output length. For many such functions, the
final output length `outlen` might be different (shorter) than the first calls.

