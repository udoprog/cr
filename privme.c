#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

#include <glib.h>

#include "error.h"

gchar*  g_private_key = NULL;
gchar*  g_hash = NULL;
int     g_print_settings = 0;
int     g_print_help = 0;
gchar*  g_in = NULL;
FILE*   g_in_fp = NULL;
FILE*   g_hash_fp = NULL;

void setup_globals() {
  g_private_key    = NULL;
  g_hash           = NULL;
  g_print_settings = 0;
  g_print_help     = 0;

  error_setup();
}

int exit_usage() {
  printf("Usage: privme <command> [opts]\n");
  printf("commands: sign, verify\n");
  printf(" -h: Print help text about <command>\n");
  exit(1);
}

void openssl_error_print() {
  char buffer[1024];
  long code;

  error_print(stderr);

  SSL_load_error_strings();

  while ((code = ERR_get_error()) != 0) {
    ERR_error_string_n(code, buffer, 1024);
    fprintf(stderr, "openssl:%s\n", buffer);
  }
}

void errno_print(const char* func) {
  error_print(stderr);
  fprintf(stderr, "errno:%s:%s\n", func, strerror(errno));
}

typedef int (*command_callback)(void);

struct command_entry {
  const char* opts;
  const char* command;
  const command_callback callback;
  const command_callback help_callback;
};

int sign_callback_help() {
  printf("Usage: privme sign -I <identity>\n");
  printf("-i <file>: Read input from <file> instead of stdin\n");
  return 0;
}

gboolean read_private_key(const char* path, RSA** rsa) {
  FILE* fp;

  fp = fopen(path, "rb");

  if (fp == NULL) {
    errno_print("fopen");
    return FALSE;
  }

  *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);

  if (*rsa == NULL) {
    error_push(ERROR_PRIVATE_KEY);
    openssl_error_print();
    return FALSE;
  }

  return TRUE;
}

gboolean sha1_digest_fp(FILE* fp, unsigned char* digest) {
  char buffer[4096];
  size_t r;

  SHA_CTX ctx;

  SHA1_Init(&ctx);
  
  while (!feof(fp)) {
    r = fread(buffer, 1, 4096, fp);

    if (ferror(fp)) {
      SHA1_Final(digest, &ctx);
      errno_print("fread");
      return FALSE;
    }

    SHA1_Update(&ctx, buffer, (unsigned long)r);
  }

  SHA1_Final(digest, &ctx);
  return TRUE;
}

gboolean private_key_encrypt(RSA* rsa, const unsigned char* source, unsigned int slen, unsigned char* dest) {
  if (RSA_private_encrypt(slen, source, dest, rsa, RSA_PKCS1_PADDING) == -1) {
    error_push(ERROR_ENCRYPT);
    openssl_error_print();
    return FALSE;
  }

  return TRUE;
}

gboolean sha1_rsa_digest_fp(const char* private_key, FILE* fp, unsigned char** dig, gsize* len) {
  unsigned char digest[SHA_DIGEST_LENGTH];
  RSA* rsa = NULL;

  rsa = g_malloc(sizeof(RSA));

  if (!read_private_key(private_key, &rsa)) {
    g_free(rsa);
    return FALSE;
  }

  *len = RSA_size(rsa);

  *dig = g_malloc(*len);

  if (!sha1_digest_fp(fp, digest)) {
    goto rsa_error;
  }

  if (!private_key_encrypt(rsa, digest, SHA_DIGEST_LENGTH, *dig)) {
    goto rsa_error;
  }

  RSA_free(rsa);
  return TRUE;

rsa_error:
  g_free(*dig);
  RSA_free(rsa);
  return FALSE;
}

int sign_callback() {
  gchar* b64 = NULL;
  FILE* fp = stdin;
  unsigned char* dig;
  gsize size;

  if (g_private_key == NULL) {
    fprintf(stderr, "private_key: must be defined\n");
    sign_callback_help();
    return 1;
  }

  if (g_in_fp != NULL) {
    fp = g_in_fp;
  }

  if (!sha1_rsa_digest_fp(g_private_key, fp, &dig, &size)) {
    return 1;
  }

  b64 = g_base64_encode(dig, size);
  printf("%s", b64);

  g_free(dig);
  return 0;
}

int verify_callback_help() {
  printf("Usage: privme verify -I <identity> -h <file>\n");
  printf("-i <file>: Read data to digest from <file>");
  printf("-h <file>: Read digest from <file>");
  return 0;
}

gboolean read_base64_fp(FILE* fp, unsigned char** data, gsize* data_size) {
  size_t r, c, read;
  
  gchar* out;
  
  r = 0;
  c = 128;
  out = g_malloc(c);

  if (out == NULL) {
    errno_print("g_malloc");
    return FALSE;
  }
  
  while (!feof(fp)) {
    read = fread(out + r, 1, c - r, fp);

    if (ferror(fp)) {
      g_free(out);
      return FALSE;
    }

    r += read;

    if (r < c) {
      continue;
    }

    c *= 2;
    out = g_realloc(out, c);

    if (out == NULL) {
      errno_print("g_realloc");
      g_free(out);
      return FALSE;
    }
  }

  *data = g_base64_decode(out, data_size);
  return TRUE;
}

int verify_callback() {
  FILE* fp = stdin;
  unsigned char *dig, *hash;
  gsize size, hash_size;
  int i;

  if (g_private_key == NULL) {
    fprintf(stderr, "private_key: must be defined\n");
    verify_callback_help();
    return 1;
  }

  if (g_hash == NULL) {
    fprintf(stderr, "hash: must be defined\n");
    verify_callback_help();
    return 1;
  }

  if (g_in_fp != NULL) {
    fp = g_in_fp;
  }

  if (!sha1_rsa_digest_fp(g_private_key, fp, &dig, &size)) {
    return 1;
  }

  if (!read_base64_fp(g_hash_fp, &hash, &hash_size)) {
    g_free(dig);
    return 1;
  }

  if (hash_size != size) {
    goto error;
  }

  for (i = 0; i < hash_size; i++) {
    if (hash[i] != dig[i]) {
      goto error;
    }
  }

  return 0;

error:
  g_free(dig);
  g_free(hash);
  return 1;
}

#define BASE_OPTS "ph"

const struct command_entry commands[] = {
  {BASE_OPTS "I:i:", "sign", sign_callback, sign_callback_help},
  {BASE_OPTS "I:i:H:", "verify", verify_callback, verify_callback_help},
  {NULL, NULL, NULL}
};

int main(int argc, char* argv[]) {
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

  while ((entry = &commands[command_index++])->opts != NULL) {
    if (g_strcmp0(entry->command, command) == 0) {
      c = entry->callback;
      help_c = entry->help_callback;
      opts = entry->opts;
      break;
    }
  }
  
  if (c == NULL) {
    exit_usage();
  }

  setup_globals();

  while ((opt = getopt(argc, argv, opts)) != -1) {
    switch (opt) {
      case 'I':
        g_private_key = g_strdup(optarg);
        break;
      case 'H':
        g_hash = g_strdup(optarg);
        break;
      case 'i':
        g_in = g_strdup(optarg);
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
    fprintf(stderr, "print_settings = %d\n", g_print_settings);
    fprintf(stderr, "private_key    = %s\n", g_private_key);
    fprintf(stderr, "in             = %s\n", g_in);
  }

  if (g_in != NULL) {
    g_in_fp = fopen(g_in, "rb");

    if (g_in_fp == NULL) {
      errno_print("fopen");
      goto exit_cleanup;
    }
  }

  if (g_hash != NULL) {
    g_hash_fp = fopen(g_hash, "rb");

    if (g_hash_fp == NULL) {
      errno_print("fopen");
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

  if (g_hash_fp != NULL) {
    fclose(g_hash_fp);
  }

  return ret;
}
