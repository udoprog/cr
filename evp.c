#include <openssl/pem.h>
#include <openssl/dsa.h>

#include <stdio.h>

#include <assert.h>

#include "string.h"
#include "evp.h"

EVP_PKEY* evp_open_private(const char* path)
{
  FILE* path_fp;

  path_fp = fopen(path, "rb");

  if (path_fp == NULL)
  {
    return NULL;
  }

  return PEM_read_PrivateKey(path_fp, NULL, NULL, NULL);
}

EVP_PKEY* evp_open_public(const char* path)
{
  FILE* path_fp;

  path_fp = fopen(path, "rb");

  if (path_fp == NULL)
  {
    return NULL;
  }

  return PEM_read_PUBKEY(path_fp, NULL, NULL, NULL);
}

int sha1_digest_fp(FILE* fp, unsigned char* digest)
{
  char buffer[EVP_IO_BUFFER_SIZE];
  size_t r;

  SHA_CTX ctx;

  fseek(fp, 0, SEEK_SET);

  SHA1_Init(&ctx);
  
  while (!feof(fp)) {
    r = fread(buffer, 1, EVP_IO_BUFFER_SIZE, fp);

    if (ferror(fp)) {
      SHA1_Final(digest, &ctx);
      return 0;
    }

    SHA1_Update(&ctx, buffer, (unsigned long)r);
  }

  SHA1_Final(digest, &ctx);
  return 1;
}

int evp_sign_dsa(DSA* dsa, const unsigned char* digest, unsigned int digest_length, string* s)
{
  unsigned int tmp_size;
  unsigned char* tmp_base;

  tmp_base = malloc(DSA_size(dsa));

  if (!DSA_sign(0, digest, digest_length, tmp_base, &tmp_size, dsa)) {
    free(tmp_base);
    return 0;
  }

  string_set(s, tmp_base, tmp_size);

  assert(string_size(s) == tmp_size);

  free(tmp_base);
  return 1;
}

int evp_sign_rsa(RSA* rsa, const unsigned char* digest, unsigned int digest_length, string* s)
{
  unsigned int tmp_size;
  unsigned char* tmp_base;

  tmp_base = malloc(RSA_size(rsa));

  if (!RSA_sign(NID_sha1, digest, digest_length, tmp_base, &tmp_size, rsa)) {
    free(tmp_base);
    return 0;
  }

  string_set(s, tmp_base, tmp_size);

  assert(string_size(s) == tmp_size);

  free(tmp_base);
  return 1;
}

int evp_sign(EVP_PKEY* evp, FILE* fp, string* s)
{
  unsigned char digest[SHA_DIGEST_LENGTH];
  unsigned int digest_length = SHA_DIGEST_LENGTH;

  if (!sha1_digest_fp(fp, digest)) {
    return 0;
  }

  switch (EVP_PKEY_type(evp->type)) {
    case EVP_PKEY_DSA:
      return evp_sign_dsa(EVP_PKEY_get1_DSA(evp), digest, digest_length, s);
    case EVP_PKEY_RSA:
      return evp_sign_rsa(EVP_PKEY_get1_RSA(evp), digest, digest_length, s);
  }

  return 0;
}

int evp_verify_dsa(DSA* dsa, FILE* fp, string* s)
{
  unsigned char digest[SHA_DIGEST_LENGTH];

  if (!sha1_digest_fp(fp, digest)) {
    return 0;
  }

  if (DSA_verify(0, digest, SHA_DIGEST_LENGTH, s->base, s->size, dsa)) {
    return 1;
  }

  return 0;
}

int evp_verify_rsa(RSA* rsa, FILE* fp, string* s)
{
  unsigned char digest[SHA_DIGEST_LENGTH];

  if (!sha1_digest_fp(fp, digest)) {
    return 0;
  }

  if (RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, s->base, s->size, rsa)) {
    return 1;
  }

  return 0;
}

int evp_verify(EVP_PKEY* evp, FILE* fp, string* s)
{
  switch (EVP_PKEY_type(evp->type)) {
    case EVP_PKEY_DSA:
      return evp_verify_dsa(EVP_PKEY_get1_DSA(evp), fp, s);
    case EVP_PKEY_RSA:
      return evp_verify_rsa(EVP_PKEY_get1_RSA(evp), fp, s);
  }

  return 0;
}

/*
int main(int argc, char* argv[]) {
  EVP_PKEY* evp_priv = evp_open_private("id_rsa");
  EVP_PKEY* evp_pub = evp_open_private("id_rsa");

  if (evp_priv == NULL) {
    fprintf(stderr, "Failed to open evp key\n");
    return 1;
  }

  if (evp_pub == NULL) {
    fprintf(stderr, "Failed to open evp key\n");
    return 1;
  }

  string* s = string_new();

  FILE* passwd = fopen("/etc/passwd", "rb");

  if (!evp_sign(evp_priv, passwd, s)) {
    printf("Failed to sign\n");
  }

  if (evp_verify(evp_pub, passwd, s)) {
    printf("Signature is valid\n");
  }
  else {
    printf("Signature is invalid\n");
  }

  long code;
  char buffer[1024];

  ERR_load_crypto_strings();

  while ((code = ERR_get_error()) != 0) {
    ERR_error_string_n(code, buffer, 1024);
    fprintf(stderr, "openssl:%s\n", buffer);
  }

  string_free(s);
  EVP_PKEY_free(evp_priv);
  EVP_PKEY_free(evp_pub);
}
*/
