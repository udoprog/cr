#include "rsa.h"

#include "bool.h"
#include "error.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

int _rsa_sha1_file(FILE*, unsigned char*);

typedef int (*key_function) (const char*, EVP_PKEY**);
int _rsa_read_private_key(const char*, EVP_PKEY**);
int _rsa_read_public_key(const char*, EVP_PKEY**);

typedef int (*cipher_function) (EVP_PKEY*, const unsigned char*, unsigned int, unsigned char*, int*);

int _rsa_encrypt(EVP_PKEY*, const unsigned char*, unsigned int, unsigned char*, int*);
int _rsa_decrypt(EVP_PKEY*, const unsigned char*, unsigned int, unsigned char*, int*);

int _rsa_cipher(cipher_function, key_function, const char*, const unsigned char*, unsigned int, unsigned char**, int*);

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

int _rsa_encrypt(EVP_PKEY* evp_pkey, const unsigned char* source, unsigned int source_size, unsigned char* dest, int* dest_size)
{
  RSA* rsa = NULL;

  int tmp_dest_size;

  switch (EVP_PKEY_type(evp_pkey->type)) {
    case EVP_PKEY_RSA:
      rsa = EVP_PKEY_get1_RSA(evp_pkey);

      if ((tmp_dest_size = RSA_private_encrypt(source_size, source, dest, rsa, RSA_PKCS1_PADDING)) == -1) {
        error_push(ERROR_ENCRYPT);
        error_all_print("RSA_private_encrypt");
        return FALSE;
      }
      break;
    case NID_undef:
    default:
      error_push(ERROR_UNSUPPORTED_ALGORITHM);
      return FALSE;
  }

  *dest_size = tmp_dest_size;

  return TRUE;
}

int _rsa_decrypt(EVP_PKEY* evp_pkey, const unsigned char* source, unsigned int source_size, unsigned char* dest, int* dest_size)
{
  RSA* rsa = NULL;
  /*DSA* dsa = NULL;*/

  int tmp_dest_size;

  switch (EVP_PKEY_type(evp_pkey->type)) {
    case NID_undef:
      break;
    case EVP_PKEY_RSA:
      rsa = EVP_PKEY_get1_RSA(evp_pkey);

      if ((tmp_dest_size = RSA_public_decrypt(source_size, source, dest, rsa, RSA_PKCS1_PADDING)) == -1) {
        error_push(ERROR_ENCRYPT);
        error_all_print("RSA_public_decrypt");
        return FALSE;
      }
      break;
    default:
      error_push(ERROR_UNSUPPORTED_ALGORITHM);
      return FALSE;
  }

  *dest_size = tmp_dest_size;

  return TRUE;
}

int _rsa_read_private_key(const char* path, EVP_PKEY** evp_pkey)
{
  EVP_PKEY* tmp_evp_pkey;
  FILE* path_fp;

  path_fp = fopen(path, "rb");

  if (path_fp == NULL) {
    error_all_print("fopen");
    return FALSE;
  }

  tmp_evp_pkey = PEM_read_PrivateKey(path_fp, NULL, NULL, NULL);

  if (tmp_evp_pkey == NULL) {
    error_push(ERROR_PRIVATE_KEY);
    error_all_print("PEM_read_PrivateKey");
    return FALSE;
  }

  *evp_pkey = tmp_evp_pkey;

  return TRUE;
}

int _rsa_read_public_key(const char* path, EVP_PKEY** evp_pkey)
{
  EVP_PKEY *tmp_evp_pkey;
  FILE* path_fp;

  path_fp = fopen(path, "r");

  if (path_fp == NULL) {
    error_all_print("fopen");
    return FALSE;
  }

  printf("path: %s\n", path);

  tmp_evp_pkey = PEM_read_PUBKEY(path_fp, NULL, NULL, NULL);

  if (tmp_evp_pkey == NULL) {
    error_push(ERROR_PUBLIC_KEY);
    error_all_print("PEM_read_PublicKey");
    return FALSE;
  }

  *evp_pkey = tmp_evp_pkey;

  return TRUE;
}

int _rsa_cipher(cipher_function cipher, key_function key, const char* key_path, const unsigned char* source, unsigned int source_length, unsigned char** dest, int* dest_length)
{
  unsigned char* tmp_dest;
  int tmp_dest_length;

  RSA* rsa;
  DSA* dsa;

  EVP_PKEY evp_pkey;
  EVP_PKEY* tmp_evp_pkey = &evp_pkey;

  if (!key(key_path, &tmp_evp_pkey)) {
    return FALSE;
  }

  switch (EVP_PKEY_type(tmp_evp_pkey->type)) {
    case NID_undef:
      break;
    case EVP_PKEY_RSA:
      rsa = EVP_PKEY_get1_RSA(tmp_evp_pkey);
      tmp_dest_length = RSA_size(rsa);
      break;
    case EVP_PKEY_DSA:
      dsa = EVP_PKEY_get1_DSA(tmp_evp_pkey);
      tmp_dest_length = DSA_size(dsa);
      break;
    default:
      error_push(ERROR_UNSUPPORTED_ALGORITHM);
      return FALSE;
  }

  tmp_dest = malloc(tmp_dest_length);

  if (tmp_dest == NULL) {
    error_all_print("malloc");
    goto error;
  }

  if (!cipher(tmp_evp_pkey, source, source_length, tmp_dest, &tmp_dest_length)) {
    error_all_print("cipher");
    goto error;
  }

  *dest = tmp_dest;
  *dest_length = tmp_dest_length;

  EVP_PKEY_free(tmp_evp_pkey);
  return TRUE;

error:
  free(tmp_dest);
  EVP_PKEY_free(tmp_evp_pkey);
  return FALSE;
}

/**
 *
 */
int rsa_signature(const char* private_key, FILE* data_fp, unsigned char** dest, int* dest_length)
{
  unsigned char digest[SHA_DIGEST_LENGTH];
  fseek(data_fp, 0, SEEK_SET);

  if (!_rsa_sha1_file(data_fp, digest)) {
    return FALSE;
  }

  if (!_rsa_cipher(_rsa_encrypt, _rsa_read_private_key, private_key, digest, SHA_DIGEST_LENGTH, dest, dest_length)) {
    return FALSE;
  }

  return TRUE;
}

int rsa_public_decrypt(const char* public_key, const unsigned char* source, int source_length, unsigned char** dest, int* dest_length)
{
  if (!_rsa_cipher(_rsa_decrypt, _rsa_read_public_key, public_key, source, source_length, dest, dest_length)) {
    return FALSE;
  }

  return TRUE;
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
  return FALSE;
}
