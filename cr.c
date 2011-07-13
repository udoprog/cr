#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "cr.h"
#include "error.h"
#include "base64.h"
#include "bool.h"
#include "string.h"
#include "evp.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/engine.h>

char* g_private_key           = NULL;
char* g_public_key            = NULL;
char* g_signature             = NULL;
char* g_in                    = NULL;
char* g_out                   = NULL;
FILE* g_in_fp                 = NULL;
FILE* g_out_fp                = NULL;
FILE* g_signature_fp          = NULL;
int   g_print_settings        = 0;
int   g_print_help            = 0;
int   g_failfast              = 0;
enum EVP_DIGEST_TYPE g_digest = evp_none;

#define xfree(var) if (var != NULL) { free(var); var=NULL; }
#define xfclose(var) if (var != NULL) { fclose(var); var=NULL; }

int exit_usage() {
  printf("Usage: cr <command> [opts]\n");
  printf("commands: sign, verify\n");
  printf(" -help:     Print help text about <command>\n");
  printf(" -debug:    Print debug information\n");
  printf(" -failfast: Never prompt for password, fail instead\n");
  exit(1);
}

int sign_callback_help() {
  printf("Usage: cr sign -priv <key-file>\n");
  printf("-priv <key-file> - Private key to use when signing\n");
  printf("-in   <in-file>  - Read data to sign from file, defaults to stdin\n");
  printf("-out  <out-file> - Write signature to file, default to stdout\n");
  return 0;
}

int verify_callback_help() {
  printf("Usage: cr verify -priv/-pub <key-file> -sig <signature>\n");
  printf("-priv <key-file> Private key to use when verifying data\n");
  printf("-pub  <key-file> Public key to use when verifying data\n");
  printf("-in   <in-file>  Read data to check from file\n");
  printf("-sig  <file>     Read signature from file\n");
  return 0;
}

int read_password(const char* path, char* buf, int size)
{
  char prompt[1025];
  char* pass;
  int len;

  if (g_failfast) {
    return 0;
  }

  if (snprintf(prompt, 1024, "Enter password to open '%s':", path) < 0) {
    fprintf(stderr, "failed to format prompt\n");
    return 0;
  }

  pass = getpass(prompt);

  if (pass == NULL) {
    fprintf(stderr, "failed to retrieve password\n");
    return 0;
  }

  len = strlen(pass);

  if (len > size) {
    len = size;
  }

  memcpy(buf, pass, len);
  free(pass);
  return len;
}

int generate_callback_help() {
  printf("Usage: cr generate\n");
  return 0;
}

int sign_callback() {
  FILE* fp_in = stdin;
  FILE* fp_out = stdout;

  string* s = NULL;
  EVP_PKEY* evp = NULL;
  enum EVP_DIGEST_TYPE type = g_digest;

  if (g_private_key == NULL) {
    fprintf(stderr, "private_key: must be defined\n");
    sign_callback_help();
    return 1;
  }

  s = string_new();

  if (!evp_open_private(&evp, g_private_key, &read_password)) {
    fprintf(stderr, "could not open private key\n");
    error_all_print("sign_callback");
    goto error;
  }

  if (g_in_fp != NULL) {
    fp_in = g_in_fp;
  }

  if (g_out_fp != NULL) {
    fp_out = g_out_fp;
  }

  if (type == evp_none) {
    type = evp_sha1;
  }

  if (!evp_sign(evp, type, fp_in, s)) {
    error_all_print("sign_callback");
    goto error;
  }

  if (fwrite(EVP_DIGEST_TYPE_NAMES[type], EVP_DIGEST_TYPE_SIZES[type], 1, fp_out) != 1) {
    goto error;
  }

  if (fwrite(":", 1, 1, fp_out) != 1) {
    goto error;
  }

  if (!base64_fencode(fp_out, string_base(s), string_size(s))) {
    error_all_print("sign_callback");
    goto error;
  }

  EVP_PKEY_free(evp);
  string_free(s);
  return 0;

error:
  EVP_PKEY_free(evp);
  string_free(s);
  return 1;
}

int verify_internal_callback_ref(EVP_PKEY* evp, enum EVP_DIGEST_TYPE type, FILE* fp, string* ref)
{
  int r;

  r = evp_verify(evp, type, fp, ref);

  switch (r)
  {
  case EVP_ERROR:
    error_all_print("verify_internal_callback");
    printf("VERIFY ERROR\n");
    return 2;
  case EVP_FAILURE:
    printf("VERIFY FAILURE\n");
    return 1;
  }

  printf("VERIFY SUCCESS\n");
  return 0;
}

int extract_type(FILE* fp, enum EVP_DIGEST_TYPE* type)
{
  char buffer[16];
  int buffer_size;
  int i;
  int c;

  buffer_size = 0;

  while ((c = fgetc(fp)) != ':') {
    if (c == EOF) {
      error_push(ERROR_EOF);
      return 0;
    }

    buffer[buffer_size++] = (char)c;
  }

  for (i = 0; i < EVP_DIGEST_TYPE_COUNT; i++) {
    int current_size = EVP_DIGEST_TYPE_SIZES[i];

    if (current_size != buffer_size) {
      continue;
    }

    if (strncmp(buffer, EVP_DIGEST_TYPE_NAMES[i], current_size) == 0) {
      *type = i;
      return 1;
    }
  }

  error_push(ERROR_NOTFOUND);
  return 0;
}

int verify_internal_callback(EVP_PKEY* evp) {
  FILE* fp = stdin;
  unsigned char* s_ref = NULL;
  int i_ref = 0;
  int ret;

  enum EVP_DIGEST_TYPE type;

  string* ref;

  if (g_in_fp != NULL) {
    fp = g_in_fp;
  }

  if (!extract_type(g_signature_fp, &type)) {
    error_all_print("verify_internal_callback");
    return 1;
  }

  if (g_digest != evp_none && type != g_digest) {
    error_push(ERROR_DIGEST_TYPE_MISMATCH);
    error_all_print("verify_internal_callback");
    return 1;
  }

  if (!base64_fdecode(g_signature_fp, &s_ref, &i_ref)) {
    error_all_print("verify_internal_callback");
    return 1;
  }

  ref = string_new_p(s_ref, i_ref);

  ret = verify_internal_callback_ref(evp, type, fp, ref);

  free(s_ref);
  string_free(ref);
  return ret;
}

int verify_callback() {
  EVP_PKEY* evp = NULL;
  int ret;

  if (g_signature == NULL) {
    fprintf(stderr, "signature: must be defined\n");
    verify_callback_help();
    return 1;
  }

  if (g_public_key != NULL) {
    if (!evp_open_public(&evp, g_public_key, &read_password)) {
      fprintf(stderr, "could not open key\n");
      goto error;
    }
  }
  else if (g_private_key != NULL) {
    if (!evp_open_private(&evp, g_private_key, &read_password)) {
      fprintf(stderr, "could not open key\n");
      goto error;
    }
  }
  else {
    fprintf(stderr, "public (-pub) or private (-priv) key must be specified\n");
    verify_callback_help();
    goto error;
  }

  ret = verify_internal_callback(evp);
  EVP_PKEY_free(evp);
  return ret;
error:
  EVP_PKEY_free(evp);
  return 1;
}

int generate_callback() {
  return 0;
}

const struct command_entry commands[] = {
  {"sign",      sign_callback, sign_callback_help},
  {"verify",    verify_callback, verify_callback_help},
  {"generate",  generate_callback, generate_callback_help},
  {NULL, NULL, NULL}
};

const char* get_arg(int i, int argc, char* argv[]) {
  if (i + 1 >= argc) {
    fprintf(stderr, "%s: expected argument to option '%s'", argv[0], argv[i]);
    exit(1);
  }

  return argv[i+1];
}

int main(int argc, char* argv[])
{
  int ret = 1;
  const char* command = NULL;
  command_callback c = NULL;
  command_callback help_c = NULL;
  const struct command_entry* entry = NULL;
  int command_index = 0;

  OpenSSL_add_all_algorithms();

  if (argc < 2) {
    exit_usage();
  }

  command = argv[1];

  while ((entry = &commands[command_index++])->command != NULL)
  {
    if (strcmp(entry->command, command) == 0) {
      c = entry->callback;
      help_c = entry->help_callback;
      break;
    }
  }
  
  if (c == NULL) {
    printf("no such comnand '%s'\n", command);
    exit_usage();
  }

  error_setup();

  {
    int i;
    for (i = 2; i < argc; i++) {
      if (strcmp(argv[i], "-pub") == 0) {
        g_public_key = strdup(get_arg(i, argc, argv));
        i += 1;
      }
      else if (strcmp(argv[i], "-priv") == 0) {
        g_private_key = strdup(get_arg(i, argc, argv));
        i += 1;
      }
      else if (strcmp(argv[i], "-sig") == 0) {
        g_signature = strdup(get_arg(i, argc, argv));
        i += 1;
      }
      else if (strcmp(argv[i], "-in") == 0) {
        g_in = strdup(get_arg(i, argc, argv));
        i += 1;
      }
      else if (strcmp(argv[i], "-out") == 0) {
        g_out = strdup(get_arg(i, argc, argv));
        i += 1;
      }
      else if (strcmp(argv[i], "-failfast") == 0) {
        g_failfast = 1;
      }
      else if (strcmp(argv[i], "-sha1") == 0) {
        g_digest = evp_sha1;
      }
      else if (strcmp(argv[i], "-md5") == 0) {
        g_digest = evp_md5;
      }
      else if (strcmp(argv[i], "-debug") == 0) {
        g_print_settings = 1;
      }
      else if (strcmp(argv[i], "-help") == 0) {
        g_print_help = 1;
      }
      else {
        fprintf(stderr, "%s: unknown option '%s'\n", argv[0], argv[i]);
        exit_usage();
        exit(EXIT_FAILURE);
      }
    }
  }

  if (g_print_settings) {
    fprintf(stderr, "private_key = %s\n", g_private_key);
    fprintf(stderr, "public_key  = %s\n", g_public_key);
    fprintf(stderr, "signature   = %s\n", g_signature);
    fprintf(stderr, "in          = %s\n", g_in);
    fprintf(stderr, "out         = %s\n", g_out);
  }


  if (g_in != NULL) {
    g_in_fp = fopen(g_in, "rb");

    if (g_in_fp == NULL) {
      error_all_print("main");
      goto exit_cleanup;
    }
  }

  if (g_out != NULL) {
    g_out_fp = fopen(g_out, "wb");

    if (g_out_fp == NULL) {
      error_all_print("main");
      goto exit_cleanup;
    }
  }

  if (g_signature != NULL) {
    g_signature_fp = fopen(g_signature, "rb");

    if (g_signature_fp == NULL) {
      error_all_print("main");
      goto exit_cleanup;
    }
  }

  if (g_print_help) {
    c = help_c;
  }

  ret = c();

exit_cleanup:
  xfclose(g_in_fp);
  xfclose(g_out_fp);
  xfclose(g_signature_fp);

  xfree(g_private_key);
  xfree(g_public_key);
  xfree(g_signature);
  xfree(g_in);
  xfree(g_out);

  CONF_modules_free();
  CONF_modules_unload(1);

  ERR_remove_state(0);
  ERR_free_strings();

  EVP_cleanup();
  ENGINE_cleanup();
  CRYPTO_cleanup_all_ex_data();
  return ret;
}
