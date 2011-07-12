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

int string_set(string* s, const char* source, int size)
{
  string_set_offset(s, source, 0, size);
}

int string_append(string* s, const char* source, int size)
{
  string_set_offset(s, source, s->size, size);
}

int string_set_offset(string* s, const char* source, int offset, int size)
{
  while (offset + size + 1 > s->_bss) {
    if (string_inc(s) == 0) {
      return 0;
    }
  }

  memcpy(s->base + offset, source, size);
  s->base[offset + size] = '\0';
  s->size = offset + size;
  memset(s->base + offset + size, 0x00, s->_bss - offset - size);

  return s->size;
}
