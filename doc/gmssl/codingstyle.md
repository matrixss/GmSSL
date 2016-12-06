# The GmSSL Coding Style

This coding style has some differences with the current OpenSSL coding style
(see [1]). As coding style is very personal and currently I am still the major contributor, the GmSSL coding style is what I prefer to use. The major reason of this coding style is that the maintenance is easier than the OpenSSL coding style.

## Basic Rule

* This coding style is only used in the new source files written and added by the GmSSL project. 
* If we modify and existing OpenSSL source files such as `include/openssl/evp.h`, we will strictly follow the OpenSSL coding style.
* If the file is copied from existing OpenSSL source file and with minor modifies, then we will also follow the OpenSSL coding style. This means that the next time we modify new version of the file will be easy.

## Details

### Use tabs with 8-character width.

The OpenSSL coding style is derived from the Linux kernel coding style (see
[2]) but it changed the indentation from tab to 4-character width spaces. The
GmSSL coding style follows the kernel's style.

### Broken lines with one more tab indent.

Because it is easier to type (without help of editors) and with 8-character width ident it is still easy to see.


### Always using braces.

Wrapping with barces even for a single statement. This is different with the Linux kernel style and the OpenSSL style.The reason for writing the unnecessary braces is for future debugging and error handling. And it is less error-prone for developers not familar the code.

### Push errors when possible.

For debugging reasons.

### Wrapping changes with define micros

For future maintenance.

## References

 1. OpenSSL coding style. [https://www.openssl.org/policies/codingstyle.txt]
 2. Linux kernel coding style. [https://www.kernel.org/doc/Documentation/CodingStyle]


------

Copyright 2016 The GmSSL Project. All Rights Reserved.