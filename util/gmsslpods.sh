#!/bin/sh
#
# This script replace the "openssl" command name string to "gmssl" of the pod
# files in current folder (normally doc/apps/).

sed -i -- 's/openssl/gmssl/g' *.pod
sed -i -- 's/gmssl.cnf/openssl.cnf/g' *.pod
sed -i -- 's/www.gmssl.org/www.openssl.org/g' *.pod
sed -i -- 's/OpenSSL/GmSSL/g' *.pod
sed -i -- 's/GmSSL Project Authors/OpenSSL Project Authors/g' *.pod
rm -f *.pod--

