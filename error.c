#include <stdlib.h>
#include <stdio.h>

#include "error.h"

long g_errors[MAX_ERRORS];
long g_error_pos = 0;

const char* g_error_strings[] = {
  "Invalid error code",
  "Private key error",
  "Encryption error"
};

void error_push(long code) {
  if (g_error_pos >= MAX_ERRORS) {
    error_push(ERROR_INVALID_CODE);
    error_exit();
  }

  if (code >= sizeof(g_error_strings)) {
    error_push(ERROR_INVALID_CODE);
    error_exit();
  }

  g_errors[g_error_pos] = code;
  g_error_pos += 1;
}

long error_pop() {
  long code = 0;

  if (g_error_pos <= 0) {
    g_error_pos = 0;
    return 0;
  }

  code = g_errors[g_error_pos - 1];

  g_error_pos -= 1;
  return code;
}

const char* error_str(long code) {
  return g_error_strings[code-1];
}

void error_print(FILE* fp) {
  long code;
  int i = 1;

  while ((code = error_pop()) != 0) {
    fprintf(fp, "error#%03d:%s\n", i++, error_str(code));
  }
}

void error_exit() {
  fprintf(stderr, "Exiting with errors\n");
  error_print(stderr);
  exit(1);
}

void error_setup() {
  long i;
  for (i = 0; i < MAX_ERRORS; i++) {
    g_errors[i] = 0;
  }
}
