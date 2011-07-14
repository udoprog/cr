/*
 * Copyright (c) 2011, John-John Tedro <johnjohn.tedro@toolchain.eu>
 * All rights reserved.
 * see LICENSE
 */
#ifndef _ERROR_H_
#define _ERROR_H_

#define MAX_ERRORS 1000

#define ERROR_INVALID_CODE 1
#define ERROR_PRIVATE_KEY 2
#define ERROR_PUBLIC_KEY 3
#define ERROR_ENCRYPT 4
#define ERROR_HASH_SIZE 5
#define ERROR_UNSUPPORTED_ALGORITHM 6
#define ERROR_EOF 7
#define ERROR_READ 8
#define ERROR_NOTFOUND 9
#define ERROR_DSA_SHA1 10
#define ERROR_DIGEST_TYPE_MISMATCH 11

void          error_setup();
void          error_push(long);
long          error_pop();
const char*   error_str(long);
void          error_print(FILE*, const char*);
void          error_errno_print(FILE* fp, const char*);
void          error_all_print(const char* func);

#endif /* _ERROR_H_ */
