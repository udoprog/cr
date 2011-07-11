#ifndef _ERROR_H_
#define _ERROR_H_

#define MAX_ERRORS 1000

#define ERROR_INVALID_CODE 1
#define ERROR_PRIVATE_KEY 2
#define ERROR_ENCRYPT 3

void          error_setup();
void          error_push(long);
long          error_pop();
const char*   error_str(long);
void          error_print(FILE*);
void          error_exit();

#endif /* _ERROR_H_ */
