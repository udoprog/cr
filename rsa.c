#include "rsa.h"

#include "bool.h"
#include "error.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

int _rsa_sha1_file(FILE*, unsigned char*);
int _rsa_read_private_key(const char*, RSA**);
int _rsa_read_public_key(const char*, RSA**);
int _rsa_encrypt(RSA*, const unsigned char*, unsigned int, unsigned char*, int*);
int _rsa_decrypt(RSA*, const unsigned char*, unsigned int, unsigned char*, int*);

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

int _rsa_encrypt(RSA* rsa, const unsigned char* source, unsigned int source_size, unsigned char* dest, int* dest_size)
{
  int tmp_dest_size;

  if ((tmp_dest_size = RSA_private_encrypt(source_size, source, dest, rsa, RSA_PKCS1_PADDING)) == -1) {
    error_push(ERROR_ENCRYPT);
    error_all_print("RSA_private_encrypt");
    return FALSE;
  }

  *dest_size = tmp_dest_size;

  return TRUE;
}

int _rsa_decrypt(RSA* rsa, const unsigned char* source, unsigned int source_size, unsigned char* dest, int* dest_size)
{
  int tmp_dest_size;

  if ((tmp_dest_size = RSA_public_decrypt(source_size, source, dest, rsa, RSA_PKCS1_PADDING)) == -1) {
    error_push(ERROR_ENCRYPT);
    error_all_print("RSA_public_decrypt");
    return FALSE;
  }

  *dest_size = tmp_dest_size;
  return TRUE;
}

int _rsa_read_private_key(const char* path, RSA** rsa)
{
  EVP_PKEY* pkey;
  RSA* tmp_rsa;
  FILE* path_fp;

  path_fp = fopen(path, "rb");

  if (path_fp == NULL) {
    error_all_print("fopen");
    return FALSE;
  }

  pkey = PEM_read_PrivateKey(path_fp, NULL, NULL, NULL);

  if (pkey == NULL) {
    error_push(ERROR_PRIVATE_KEY);
    error_all_print("PEM_read_PrivateKey");
    return FALSE;
  }

  tmp_rsa = EVP_PKEY_get1_RSA(pkey);

  if (tmp_rsa == NULL) {
    error_push(ERROR_PRIVATE_KEY);
    error_all_print("EVP_PKEY_get1_RSA");
    return FALSE;
  }

  *rsa = tmp_rsa;

  return TRUE;
}

int _rsa_read_public_key(const char* path, RSA** rsa)
{
  EVP_PKEY *pkey;
  RSA* tmp_rsa;
  FILE* path_fp;

  path_fp = fopen(path, "r");

  if (path_fp == NULL) {
    error_all_print("fopen");
    return FALSE;
  }

  printf("path: %s\n", path);

  pkey = PEM_read_PUBKEY(path_fp, NULL, NULL, NULL);

  if (pkey == NULL) {
    error_push(ERROR_PUBLIC_KEY);
    error_all_print("PEM_read_PublicKey");
    return FALSE;
  }

  tmp_rsa = EVP_PKEY_get1_RSA(pkey);

  if (tmp_rsa == NULL) {
    error_push(ERROR_PRIVATE_KEY);
    error_all_print("EVP_PKEY_get1_RSA");
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

  tmp_data = malloc(RSA_size(tmp_rsa));

  fseek(data_fp, 0, SEEK_SET);

  if (!_rsa_sha1_file(data_fp, digest)) {
    goto error;
  }

  if (!_rsa_encrypt(tmp_rsa, digest, SHA_DIGEST_LENGTH, tmp_data, &tmp_size)) {
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

int rsa_public_decrypt(const char* public_key, const unsigned char* data, int size, unsigned char** dec_data, int* dec_size)
{
  unsigned char* tmp_data;
  int tmp_size;

  RSA rsa;
  RSA* tmp_rsa = &rsa;

  if (!_rsa_read_public_key(public_key, &tmp_rsa)) {
    return FALSE;
  }

  tmp_data = malloc(RSA_size(tmp_rsa));

  if (!_rsa_decrypt(tmp_rsa, data, size, tmp_data, &tmp_size)) {
    goto error;
  }

  *dec_data = tmp_data;
  *dec_size = tmp_size;

  RSA_free(tmp_rsa);
  return TRUE;

error:
  free(tmp_data);
  RSA_free(tmp_rsa);
  return FALSE;
}

int rsa_sha1(FILE* data_fp, unsigned char** data, int* size)
{
  unsigned char* tmp_data = malloc(SHA_DIGEST_LENGTH);

  if (tmp_data == NULL) {
    error_all_print("malloc");
  }

  fseek(data_fp, 0, SEEK_SET);

  if (!_rsa_sha1_file(data_fp, tmp_data)) {
    goto error;
  }

  *data = tmp_data;
  *size = SHA_DIGEST_LENGTH;
  return TRUE;

error:
  free(tmp_data);
  return FALSE;
}

int rsa_generate_keys(const char* private_path, const char* public_path)
{
  FILE* private_fp;
  FILE* public_fp;

  RSA *rsa = RSA_generate_key(1024,65537,NULL,NULL);

  public_fp = fopen(public_path, "wb");

  if (public_fp == NULL) {
    error_all_print("fopen");
    return FALSE;
  }

  private_fp = fopen(private_path, "wb");

  if (private_fp == NULL) {
    error_all_print("fopen");
    return FALSE;
  }

  if (PEM_write_RSAPublicKey(public_fp, rsa) == 0) {
    error_all_print("PEM_write_RSAPublicKey");
    goto error;
  }

  if (PEM_write_RSAPrivateKey(private_fp, rsa, NULL,NULL,0,NULL,NULL) == 0) {
    error_all_print("PEM_write_RSAPublicKey");
    goto error;
  }

  fclose(private_fp);
  fclose(public_fp);
  return TRUE;
error:
  fclose(private_fp);
  fclose(public_fp);
  return FALSE;
}
