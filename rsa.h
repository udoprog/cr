#ifndef _RSA_H_
#define _RSA_H_

#include <stdio.h>

#define RSA_IO_BUFFER_SIZE 4096

int rsa_signature(const char*, FILE*, unsigned char**, int*);
int rsa_public_decrypt(const char*, const unsigned char*, int, unsigned char**, int*);
int rsa_sha1(FILE*, unsigned char**, int*);
int rsa_generate_keys(const char*, const char*);

#endif /*_RSA_H_*/
