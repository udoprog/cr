#include <stdlib.h>
#include <string.h>

#include "string.h"

string* string_new() {
  return string_new_s(16);
}

string* string_new_s(int size) {
  string* new = malloc(sizeof(string));

  if (size % 16 == 0) {
    new->_bss = size;
  } else {
    new->_bss = size - (size % 16) + 16;
  }

  new->_bsi = 0;

  new->base = malloc(new->_bss);
  new->size = 0;
  memset(new->base, 0x00, new->_bss);
  return new;
}


/**
 * Free up the string.
 *
 * @s the string pointer to free. Should not be used after this call.
 */
void string_free(string* s) {
  free(s->base);
  free(s);
}

int string_inc(string* s) {
  int   tmp_base_size;
  char* tmp_base;
  
  tmp_base_size = s->_bss * 2;

  tmp_base = realloc(s->base, s->_bss);

  if (tmp_base == NULL) {
    return 0;
  }

  s->base = tmp_base;
  s->_bss = tmp_base_size;
  s->_bsi += 1;

  return tmp_base_size;
}

int string_set(string* s, const char* source, int source_size)
{
  while (source_size + 1 > s->_bss) {
    if (string_inc(s) == 0) {
      return 0;
    }
  }

  memcpy(s->base, source, source_size);
  s->base[source_size] = '\0';
  s->size = source_size;
  memset(s->base + source_size, 0x00, s->_bss - source_size);

  return source_size;
}
