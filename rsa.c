#include "rsa.h"

#include "bool.h"
#include "error.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

int _rsa_sha1_file(FILE*, unsigned char*);
int _rsa_read_private_key(const char*, RSA**);
int _rsa_encrypt(RSA*, const unsigned char*, unsigned int, unsigned char*);

int _rsa_sha1_file(FILE* fp, unsigned char* digest)
{
  char buffer[RSA_IO_BUFFER_SIZE];
  size_t r;

  SHA_CTX ctx;

  SHA1_Init(&ctx);
  
  while (!feof(fp)) {
    r = fread(buffer, 1, RSA_IO_BUFFER_SIZE, fp);

    if (ferror(fp)) {
      SHA1_Final(digest, &ctx);
      error_all_print("fread");
      return FALSE;
    }

    SHA1_Update(&ctx, buffer, (unsigned long)r);
  }

  SHA1_Final(digest, &ctx);
  return TRUE;
}

int _rsa_encrypt(RSA* rsa, const unsigned char* source, unsigned int slen, unsigned char* dest)
{
  if (RSA_private_encrypt(slen, source, dest, rsa, RSA_PKCS1_PADDING) == -1) {
    error_push(ERROR_ENCRYPT);
    error_all_print("RSA_private_encrypt");
    return FALSE;
  }

  return TRUE;
}


int _rsa_read_private_key(const char* path, RSA** rsa)
{
  RSA* tmp_rsa;
  FILE* path_fp;

  path_fp = fopen(path, "rb");

  if (path_fp == NULL) {
    error_all_print("fopen");
    return FALSE;
  }

  tmp_rsa = PEM_read_RSAPrivateKey(path_fp, NULL, NULL, NULL);

  if (tmp_rsa == NULL) {
    error_push(ERROR_PRIVATE_KEY);
    error_all_print("PEM_read_RSAPrivateKey");
    return FALSE;
  }

  *rsa = tmp_rsa;

  return TRUE;
}

/**
 *
 */
int rsa_signature(const char* private_key, FILE* data_fp, unsigned char** data, int* size)
{
  unsigned char digest[SHA_DIGEST_LENGTH];
  unsigned char* tmp_data;
  int tmp_size;

  RSA rsa;
  RSA* tmp_rsa = &rsa;

  if (!_rsa_read_private_key(private_key, &tmp_rsa)) {
    return FALSE;
  }

  tmp_size = RSA_size(tmp_rsa);

  tmp_data = malloc(tmp_size);

  fseek(data_fp, 0, SEEK_SET);

  if (!_rsa_sha1_file(data_fp, digest)) {
    goto error;
  }

  if (!_rsa_encrypt(tmp_rsa, digest, SHA_DIGEST_LENGTH, tmp_data)) {
    goto error;
  }

  *data = tmp_data;
  *size = tmp_size;

  RSA_free(tmp_rsa);
  return TRUE;

error:
  free(tmp_data);
  RSA_free(tmp_rsa);
  return FALSE;
}
