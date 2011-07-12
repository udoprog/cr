#ifndef _STRING_H_
#define _STRING_H_

typedef struct {
  char* base;
  int size;

  int _bss;
  int _bsi;
} string;

string* string_new();
string* string_new_s(int);
void string_free(string*);

int string_inc(string*);
int string_set(string*, const char*, int);

#endif /* _STRING_H_ */
