#include <stdlib.h>
#include <string.h>

#include "string.h"

string* string_new() {
  return string_new_s(16);
}

string* string_new_p(const unsigned char* p, unsigned int s) {
  string* new = string_new_s(s);
  string_set(new, p, s);
  return new;
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

int string_inc(string* s)
{
  int            tmp_base_size;
  unsigned char* tmp_base;
  
  tmp_base_size = s->_bss * 2;

  tmp_base = realloc(s->base, tmp_base_size);

  if (tmp_base == NULL) {
    return 0;
  }

  s->base = tmp_base;
  s->_bss = tmp_base_size;
  s->_bsi += 1;

  return tmp_base_size;
}

int string_resize(string* s, int size)
{
  if (size < s->_bss) {
    return 0;
  }

  int            tmp_base_size;
  unsigned char* tmp_base;
  
  tmp_base_size = s->_bss * 2;
  s->_bsi += 1;

  while (tmp_base_size < size) {
    tmp_base_size = tmp_base_size * 2;
    s->_bsi += 1;
  }

  tmp_base = realloc(s->base, tmp_base_size);

  if (tmp_base == NULL) {
    return 0;
  }

  s->base = tmp_base;
  s->_bss = tmp_base_size;

  return tmp_base_size;
}

int string_set(string* s, const unsigned char* source, int size)
{
  return string_set_offset(s, source, 0, size);
}

int string_append(string* s, const unsigned char* source, int size)
{
  return string_set_offset(s, source, s->size, size);
}

int string_ncmp(string* s, const unsigned char* other, int n)
{
  return strncmp((const char*)s->base, (const char *)other, n);
}

int string_set_offset(string* s, const unsigned char* source, int offset, int size)
{
  while (offset + size > s->_bss) {
    if (string_inc(s) == 0) {
      return 0;
    }
  }

  memcpy(s->base + offset, source, size);
  s->size = offset + size;
  memset(s->base + offset + size, 0x00, s->_bss - offset - size);

  return s->size;
}

void string_hexdump(string* s, FILE* fp)
{
  int i = 0;

  for (i = 0; i < s->size; i++) {
    if (i % 32 == 0) {
      if (i != 0) {
        fprintf(fp, "\n");
      }
      fprintf(fp, "%04x - %04x  ", i, i + 32);
    }
    else if (i % 4 == 0) {
      fprintf(fp, " ");
    }

    fprintf(fp, "%02X", (unsigned char)s->base[i]);
  }

  fprintf(fp, "\n");
}
