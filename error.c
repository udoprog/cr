#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "error.h"

#include <openssl/err.h>

long g_errors[MAX_ERRORS];
long g_error_pos = 0;

const char* g_error_strings[] = {
  "invalid error code",
  "private key error",
  "public key error",
  "encryption error",
  "hash size mismatch"
};

void error_all_print(const char* func)
{
  char buffer[1024];
  long code;

  if (errno != 0) {
    error_errno_print(stderr, func);
  }

  if (g_error_pos > 0) {
    error_print(stderr, func);
  }

  ERR_load_crypto_strings();

  while ((code = ERR_get_error()) != 0) {
    ERR_error_string_n(code, buffer, 1024);
    fprintf(stderr, "openssl:%s\n", buffer);
  }
}

void error_errno_print(FILE* fp, const char* func)
{
  fprintf(fp, "errno:%s:%s\n", func, strerror(errno));
}

void error_push(long code)
{
  if (g_error_pos >= MAX_ERRORS) {
    error_push(ERROR_INVALID_CODE);
    error_all_print("error_push");
    exit(1);
  }

  if (code >= sizeof(g_error_strings)) {
    error_push(ERROR_INVALID_CODE);
    error_all_print("error_push");
    exit(1);
  }

  g_errors[g_error_pos] = code;
  g_error_pos += 1;
}

long error_pop()
{
  long code = 0;

  if (g_error_pos <= 0) {
    g_error_pos = 0;
    return 0;
  }

  code = g_errors[g_error_pos - 1];

  g_error_pos -= 1;
  return code;
}

const char* error_str(long code)
{
  return g_error_strings[code-1];
}

void error_print(FILE* fp, const char* func)
{
  long code;

  while ((code = error_pop()) != 0) {
    fprintf(fp, "error:%s:%04lu:%s\n", func, code, error_str(code));
  }
}

void error_setup()
{
  long i;
  for (i = 0; i < MAX_ERRORS; i++) {
    g_errors[i] = 0;
  }
}
