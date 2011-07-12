#ifndef _STRING_H_
#define _STRING_H_

#include <stdio.h>

typedef struct {
  unsigned char* base;
  unsigned int size;

  int _bss;
  int _bsi;
} string;

string* string_new();
string* string_new_s(int);
string* string_new_p(const unsigned char*, unsigned int);

void string_free(string*);

int string_ncmp(string*, const unsigned char*, int);

int string_append(string*, const unsigned char*, int);
int string_inc(string*);
int string_set(string*, const unsigned char*, int);
int string_set_offset(string*, const unsigned char*, int, int);
void string_hexdump(string*, FILE*);

#define string_size(s) ((s)->size)
#define string_base(s) ((s)->base)

#endif /* _STRING_H_ */
