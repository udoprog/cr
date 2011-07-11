#ifndef _BASE64_H_
#define _BASE64_H_

#include <stdio.h>

#define BASE64_INITIAL_BUFFER 128

int base64_fencode(FILE*, const unsigned char*, int);
int base64_fdecode(FILE*, unsigned char**, int*);

#endif /*_BASE64_H_*/
