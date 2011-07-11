#ifndef _ERROR_H_
#define _ERROR_H_

#define MAX_ERRORS 1000

#define ERROR_INVALID_CODE 1
#define ERROR_PRIVATE_KEY 2
#define ERROR_ENCRYPT 3
#define ERROR_HASH_SIZE 4

void          error_setup();
void          error_push(long);
long          error_pop();
const char*   error_str(long);
void          error_print(FILE*, const char*);
void          error_errno_print(FILE* fp, const char*);
void          error_all_print(const char* func);

#endif /* _ERROR_H_ */
