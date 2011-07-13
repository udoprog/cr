#ifndef _BASE64_H_
#define _BASE64_H_

#include <stdio.h>

#define BASE64_INITIAL_BUFFER 128

#include "string.h"

int base64_fencode(FILE*, string*);
int base64_fdecode(FILE*, string*);

#endif /*_BASE64_H_*/
