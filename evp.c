#include <openssl/pem.h>
#include <openssl/dsa.h>

#include <stdio.h>

#include <assert.h>

#include "string.h"
#include "evp.h"

const char* EVP_DIGEST_TYPE_NAMES[] = {
  "SHA1",
  "MD5"
};

const int EVP_DIGEST_TYPE_SIZES[] = {
  4,
  3
};

const int EVP_DIGEST_TYPE_COUNT = 2;

int pass_cb(char *buf, int size, int rwflag, void *u)
{
  int len;

  password_request* req = (password_request*)u;

  len = req->callback(req->path, buf, size);

  if (len <= 0) {
    return 0;
  }

  return len;
}

int evp_open_private(EVP_PKEY* evp, const char* path, password_callback callback)
{
  FILE* path_fp;
  password_request req;

  path_fp = fopen(path, "rb");

  if (path_fp == NULL)
  {
    return 0;
  }

  req.path = path;
  req.callback = callback;

  if (!PEM_read_PrivateKey(path_fp, &evp, pass_cb, &req)) {
    fclose(path_fp);
    return 0;
  }

  fclose(path_fp);
  return 1;
}

int evp_open_public(EVP_PKEY* evp, const char* path, password_callback callback)
{
  FILE* path_fp;
  password_request req;

  path_fp = fopen(path, "rb");

  if (path_fp == NULL)
  {
    return 0;
  }

  req.path = path;
  req.callback = callback;

  if (!PEM_read_PrivateKey(path_fp, &evp, pass_cb, &req)) {
    fclose(path_fp);
    return 0;
  }

  fclose(path_fp);
  return 1;
}

int digest_fp(FILE* fp, enum EVP_DIGEST_TYPE type, unsigned char* digest, unsigned int* digest_length)
{
  char buffer[EVP_IO_BUFFER_SIZE];
  size_t r;
  const EVP_MD* md;

  EVP_MD_CTX ctx;

  EVP_MD_CTX_init(&ctx);

  switch (type) {
  case evp_sha1:
    md = EVP_sha1();
    break;
  case evp_md5:
    md = EVP_md5();
    break;
  default:
    return 0;
  }
  
  EVP_DigestInit(&ctx, md);

  fseek(fp, 0, SEEK_SET);

  while (!feof(fp)) {
    r = fread(buffer, 1, EVP_IO_BUFFER_SIZE, fp);

    if (ferror(fp)) {
      return 0;
    }

    EVP_DigestUpdate(&ctx, buffer, (unsigned long)r);
  }

  EVP_DigestFinal(&ctx, digest, digest_length);
  return 1;
}

int evp_sign_dsa(DSA* dsa, enum EVP_DIGEST_TYPE type, const unsigned char* digest, unsigned int digest_length, string* s)
{
  unsigned int tmp_size;
  unsigned char* tmp_base;

  tmp_base = malloc(DSA_size(dsa));

  if (!DSA_sign(0, digest, digest_length, tmp_base, &tmp_size, dsa)) {
    free(tmp_base);
    return 0;
  }

  string_append(s, tmp_base, tmp_size);

  assert(string_size(s) == tmp_size);

  free(tmp_base);
  return 1;
}

int evp_sign_internal(EVP_PKEY* evp, EVP_MD_CTX* ctx, enum EVP_DIGEST_TYPE type, const unsigned char* digest, unsigned int digest_length, string* s)
{
  const EVP_MD* md;

  switch (type) {
  case evp_sha1:
    md = EVP_sha1();
    break;
  case evp_md5:
    md = EVP_md5();
    break;
  default:
    return 0;
  }

  EVP_MD_CTX_init(ctx);

  if (!EVP_SignInit(ctx, md)) {
    return 0;
  }

  if (!EVP_SignUpdate(ctx, digest, digest_length)) {
    return 0;
  }

  if (!EVP_SignFinal(ctx, string_base(s), &string_size(s), evp)) {
    return 0;
  }

  return 1;
}

int evp_sign(EVP_PKEY* evp, enum EVP_DIGEST_TYPE type, FILE* fp, string* s)
{
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length = 0;
  EVP_MD_CTX* ctx;
  int ret;

  if (EVP_PKEY_type(evp->type) == EVP_PKEY_DSA && type != evp_sha1) {
    return 0;
  }

  if (!digest_fp(fp, type, digest, &digest_length)) {
    return 0;
  }

  ctx = EVP_MD_CTX_create();
  string_resize(s, EVP_PKEY_size(evp));

  ret = evp_sign_internal(evp, ctx, type, digest, digest_length, s);

  EVP_MD_CTX_cleanup(ctx);
  EVP_MD_CTX_destroy(ctx);

  return ret;
}

int evp_verify_dsa(DSA* dsa, enum EVP_DIGEST_TYPE type, const unsigned char* digest, unsigned int digest_length, string* s)
{
  int r;

  r = DSA_verify(0, digest, digest_length, s->base, s->size, dsa);

  switch (r)
  {
  case 1:
    return EVP_SUCCESS;
  case -1:
    return EVP_ERROR;
  default:
    return EVP_FAILURE;
  }
}

int evp_verify_rsa(RSA* rsa, enum EVP_DIGEST_TYPE type, const unsigned char* digest, unsigned int digest_length, string* s)
{
  int verify_type;
  int r;

  switch (type) {
  case evp_sha1:
    verify_type = NID_sha1;
    break;
  case evp_md5:
    verify_type = NID_md5;
    break;
  default:
    return EVP_ERROR;
  }

  r = RSA_verify(verify_type, digest, digest_length, s->base, s->size, rsa);

  switch (r)
  {
  case 1:
    return EVP_SUCCESS;
  default:
    return EVP_FAILURE;
  }
}

/**
 * returns -1 on error
 * returns 0 on non-verified digest
 * returns 1 on verified digest
 */
int evp_verify(EVP_PKEY* evp, enum EVP_DIGEST_TYPE type, FILE* fp, string* s)
{
  unsigned char digest[SHA_DIGEST_LENGTH];
  unsigned int digest_length = 0;

  if (EVP_PKEY_type(evp->type) == EVP_PKEY_DSA && type != evp_sha1) {
    return EVP_ERROR;
  }

  if (!digest_fp(fp, type, digest, &digest_length)) {
    return EVP_ERROR;
  }

  switch (EVP_PKEY_type(evp->type)) {
    case EVP_PKEY_DSA:
      return evp_verify_dsa(EVP_PKEY_get1_DSA(evp), type, digest, digest_length, s);
    case EVP_PKEY_RSA:
      return evp_verify_rsa(EVP_PKEY_get1_RSA(evp), type, digest, digest_length, s);
  }

  return -1;
}
