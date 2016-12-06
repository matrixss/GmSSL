# CA Certificates

Typical SSL clients such as Web browsers will be shipped with a collection of CA certificates or can use the  CA certificates provided by the operating system. As the OpenSSL is not a typical client-side software, it does not provide any official CA certificates. On some operating systems such as Linux distribution it is easier to access the system certificates. But in some environment, the administrators or developers would like to have some built-in CA certificates. So the GmSSL provide such CA certificates under the `certs` folder of the source code.

The GmSSL project source code provides two collections of CA certificates:

* The CA certificates shipped with the current Mozilla FireFox browser. The GmSSL project gets these certificates directly from [CURL - CA certificates extracted from Mozilla](http://curl.haxx.se/docs/caextract.html).
* The GM Root CA Certificates. (where?)

Check if your root certificates are the most recent before using them.

-----------------------------------------------------
Copyright 2016 The GmSSL Project. All Rights Reserved.
