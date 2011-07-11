#ifndef _RSA_H_
#define _RSA_H_

#include <stdio.h>

#define RSA_IO_BUFFER_SIZE 4096

int rsa_signature(const char*, FILE*, unsigned char**, int*);

#endif /*_RSA_H_*/
