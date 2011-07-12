#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "cr.h"
#include "error.h"
#include "base64.h"
#include "bool.h"
#include "rsa.h"

char* g_private_key    = NULL;
char* g_public_key     = NULL;
char* g_signature      = NULL;
int   g_print_settings = 0;
int   g_print_help     = 0;
char* g_in             = NULL;
FILE* g_in_fp          = NULL;
char* g_out            = NULL;
FILE* g_out_fp         = NULL;
FILE* g_signature_fp   = NULL;

int exit_usage() {
  printf("Usage: cr <command> [opts]\n");
  printf("commands: sign, verify\n");
  printf(" -help:  Print help text about <command>\n");
  printf(" -debug: Print debug information\n");
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

int generate_callback_help() {
  printf("Usage: cr generate\n");
  return 0;
}

int sign_callback() {
  FILE* fp_in = stdin;
  FILE* fp_out = stdout;
  unsigned char* data = NULL;
  int size = 0;

  if (g_private_key == NULL) {
    fprintf(stderr, "private_key: must be defined\n");
    sign_callback_help();
    return 1;
  }

  if (g_in_fp != NULL) {
    fp_in = g_in_fp;
  }

  if (g_out_fp != NULL) {
    fp_out = g_out_fp;
  }

  if (!rsa_signature(g_private_key, fp_in, &data, &size)) {
    return 1;
  }

  if (!base64_fencode(fp_out, data, size)) {
    free(data);
    return 1;
  }

  free(data);
  return 0;
}

int verify_private_callback() {
  FILE* fp = stdin;
  unsigned char* s_sig = NULL;
  unsigned char* s_ref = NULL;
  int i_sig = 0;
  int i_ref = 0;

  if (g_in_fp != NULL) {
    fp = g_in_fp;
  }

  if (!rsa_signature(g_private_key, fp, &s_sig, &i_sig)) {
    return 1;
  }

  if (!base64_fdecode(g_signature_fp, &s_ref, &i_ref)) {
    goto error;
  }

  if (i_sig != i_ref) {
    error_push(ERROR_HASH_SIZE);
    error_all_print("base64_fdecode");
    goto verify_error;
  }

  {
    int i;

    for (i = 0; i < i_ref; i++) {
      if (s_ref[i] != s_sig[i]) {
        goto verify_error;
      }
    }
  }

  printf("VERIFY SUCCESS\n");

  free(s_sig);
  free(s_ref);
  return 0;

error:
  free(s_sig);
  free(s_ref);
  return 1;

verify_error:
  printf("VERIFY FAILURE\n");

  free(s_sig);
  free(s_ref);
  return 2;
}

int verify_public_callback() {
  FILE* fp = stdin;
  unsigned char* s_sig = NULL;
  unsigned char* s_ref = NULL;
  unsigned char* tmp_s_ref = NULL;
  int i_sig = 0;
  int i_ref = 0;
  int tmp_i_ref = 0;

  if (g_in_fp != NULL) {
    fp = g_in_fp;
  }

  if (!rsa_sha1(fp, &s_sig, &i_sig)) {
    return 1;
  }

  if (!base64_fdecode(g_signature_fp, &tmp_s_ref, &tmp_i_ref)) {
    goto error;
  }

  if (!rsa_public_decrypt(g_public_key, tmp_s_ref, tmp_i_ref, &s_ref, &i_ref)) {
    goto error;
  }

  if (i_sig != i_ref) {
    error_push(ERROR_HASH_SIZE);
    error_all_print("rsa_public_decrypt");
    goto verify_error;
  }

  {
    int i;

    for (i = 0; i < i_ref; i++) {
      if (s_ref[i] != s_sig[i]) {
        goto verify_error;
      }
    }
  }

  printf("VERIFY SUCCESS\n");

  free(s_sig);
  free(s_ref);
  return 0;

error:
  free(s_sig);
  free(s_ref);
  return 1;

verify_error:
  printf("VERIFY FAILURE\n");

  free(s_sig);
  free(s_ref);
  return 2;
}

int verify_callback() {
  if (g_signature == NULL) {
    fprintf(stderr, "signature: must be defined\n");
    verify_callback_help();
    return 1;
  }

  if (g_public_key != NULL) {
    return verify_public_callback();
  }

  if (g_private_key != NULL) {
    return verify_private_callback();
  }

  fprintf(stderr, "no key specified, neither -priv nor -pub\n");
  return 1;
}

int generate_callback() {
  if (!rsa_generate_keys("key.pem", "key.pub")) {
    fprintf(stderr, "Key generation failed\n");
    return 1;
  }

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
      error_all_print("fopen");
      goto exit_cleanup;
    }
  }

  if (g_out != NULL) {
    g_out_fp = fopen(g_out, "wb");

    if (g_out_fp == NULL) {
      error_all_print("fopen");
      goto exit_cleanup;
    }
  }

  if (g_signature != NULL) {
    g_signature_fp = fopen(g_signature, "rb");

    if (g_signature_fp == NULL) {
      error_all_print("fopen");
      goto exit_cleanup;
    }
  }

  if (g_print_help) {
    c = help_c;
  }

  ret = c();

exit_cleanup:
  if (g_in_fp != NULL) {
    fclose(g_in_fp);
  }

  if (g_out_fp != NULL) {
    fclose(g_out_fp);
  }

  if (g_signature_fp != NULL) {
    fclose(g_signature_fp);
  }

  return ret;
}
