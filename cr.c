#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include "cr.h"
#include "error.h"
#include "base64.h"
#include "bool.h"
#include "rsa.h"

char* g_private_key    = NULL;
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
  printf(" -h: Print help text about <command>\n");
  exit(1);
}

int sign_callback_help() {
  printf("Usage: cr sign -I <identity>\n");
  printf("-I <identity> Read identity from file\n");
  printf("-i <in-file>  Read data to sign from file\n");
  printf("-o <out-file> Write signature to file\n");
  return 0;
}

int verify_callback_help() {
  printf("Usage: cr verify -I <identity> -s <signature>\n");
  printf("-I <identity> Read identity from file\n");
  printf("-i <in-file>  Read data to check from file\n");
  printf("-s <file>     Read signature from file\n");
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

int verify_callback() {
  FILE* fp = stdin;
  unsigned char* s_sig = NULL;
  unsigned char* s_ref = NULL;
  int i_sig = 0;
  int i_ref = 0;

  if (g_private_key == NULL) {
    fprintf(stderr, "private_key: must be defined\n");
    verify_callback_help();
    return 1;
  }

  if (g_signature == NULL) {
    fprintf(stderr, "signature: must be defined\n");
    verify_callback_help();
    return 1;
  }

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

#define BASE_OPTS "ph"

const struct command_entry commands[] = {
  {BASE_OPTS "I:i:o:", "sign", sign_callback, sign_callback_help},
  {BASE_OPTS "I:i:s:", "verify", verify_callback, verify_callback_help},
  {NULL, NULL, NULL}
};

int main(int argc, char* argv[])
{
  int opt;
  int ret = 1;
  const char* command = NULL;
  const char* opts = NULL;
  command_callback c = NULL;
  command_callback help_c = NULL;
  const struct command_entry* entry = NULL;
  int command_index = 0;

  if (argc < 2) {
    exit_usage();
  }

  command = argv[1];

  while ((entry = &commands[command_index++])->opts != NULL)
  {
    if (strcmp(entry->command, command) == 0) {
      c = entry->callback;
      help_c = entry->help_callback;
      opts = entry->opts;
      break;
    }
  }
  
  if (c == NULL) {
    exit_usage();
  }

  error_setup();

  while ((opt = getopt(argc, argv, opts)) != -1) {
    switch (opt) {
      case 'I':
        g_private_key = strdup(optarg);
        break;
      case 's':
        g_signature = strdup(optarg);
        break;
      case 'i':
        g_in = strdup(optarg);
        break;
      case 'o':
        g_out = strdup(optarg);
        break;
      case 'p':
        g_print_settings = 1;
        break;
      case 'h':
        g_print_help = 1;
        break;
      default: /* '?' */
        fprintf(stderr, "Usage: %s -s <openssl-path>\n",
            argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  if (g_print_settings) {
    fprintf(stderr, "private_key = %s\n", g_private_key);
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
