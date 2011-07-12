#ifndef _EVP_H_
#define _EVP_H_

#include <openssl/evp.h>

#define EVP_IO_BUFFER_SIZE 4096

EVP_PKEY* evp_open_private(const char* path);
EVP_PKEY* evp_open_public(const char* path);

int sha1_digest_fp(FILE* fp, unsigned char* digest);
int evp_sign_dsa(DSA* dsa, const unsigned char* digest, unsigned int digest_length, string* s);
int evp_sign_rsa(RSA* rsa, const unsigned char* digest, unsigned int digest_length, string* s);
int evp_sign(EVP_PKEY* evp, FILE* fp, string* s);
int evp_verify_dsa(DSA* dsa, FILE* fp, string* s);
int evp_verify_rsa(RSA* rsa, FILE* fp, string* s);
int evp_verify(EVP_PKEY* evp, FILE* fp, string* s);

#endif /* _EVP_H_ */
