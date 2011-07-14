/*
 * Copyright (c) 2011, John-John Tedro <johnjohn.tedro@toolchain.eu>
 * All rights reserved.
 * see LICENSE
 */
#include <openssl/pem.h>
#include <openssl/dsa.h>

#include <stdio.h>

#include <assert.h>

#include "string.h"
#include "evp.h"

const char* EVP_DIGEST_TYPE_NAMES[] = {
  "SHA1",
  "DSS1",
  "MD5"
};

const int EVP_DIGEST_TYPE_SIZES[] = {
  4,
  4,
  3
};

const int EVP_DIGEST_TYPE_COUNT = 3;

const EVP_MD* get_EVP_MD(enum EVP_DIGEST_TYPE type) {
  switch (type) {
  case evp_sha1:  return EVP_sha1();
  case evp_dss1:  return EVP_dss1();
  case evp_md5:   return EVP_md5();
  default:        return NULL;
  }
}

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

int evp_open_private(EVP_PKEY** evp, const char* path, password_callback callback)
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

  *evp = PEM_read_PrivateKey(path_fp, NULL, pass_cb, &req);

  if (*evp == NULL) {
    fclose(path_fp);
    return 0;
  }

  fclose(path_fp);
  return 1;
}

int evp_open_public(EVP_PKEY** evp, const char* path, password_callback callback)
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

  *evp = PEM_read_PUBKEY(path_fp, NULL, pass_cb, &req);

  if (*evp == NULL) {
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
  case evp_dss1:
    md = EVP_dss1();
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

int evp_sign_internal(EVP_PKEY* evp, EVP_MD_CTX* ctx, enum EVP_DIGEST_TYPE type, const unsigned char* digest, unsigned int digest_length, string* s)
{
  const EVP_MD* md = NULL;

  md = get_EVP_MD(type);

  if (md == NULL) {
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

int evp_verify_internal(EVP_PKEY* evp, EVP_MD_CTX* ctx, enum EVP_DIGEST_TYPE type, const unsigned char* digest, unsigned int digest_length, string* s)
{
  const EVP_MD* md = NULL;
  int r = 0;

  md = get_EVP_MD(type);

  if (md == NULL) {
    fprintf(stderr, "evp_verify_internal: no message digest\n");
    return EVP_ERROR;
  }

  EVP_MD_CTX_init(ctx);

  if (!EVP_VerifyInit(ctx, md)) {
    fprintf(stderr, "evp_verify_iternal: EVP_VerifyInit failed\n");
    return EVP_ERROR;
  }

  if (!EVP_VerifyUpdate(ctx, digest, digest_length)) {
    fprintf(stderr, "evp_verify_internal: EVP_VerifyUpdate failed\n");
    return EVP_ERROR;
  }

  r = EVP_VerifyFinal(ctx, string_base(s), string_size(s), evp);

  switch (r) {
  case -1:
    fprintf(stderr, "evp_verify: EVP_VerifyFinal failed\n");
    return EVP_ERROR;
  case 0:
    return EVP_FAILURE;
  default:
    return EVP_SUCCESS;
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
  int ret;
  EVP_MD_CTX* ctx = NULL;

  if (evp == NULL) {
    fprintf(stderr, "evp_verify: NULL EVP_PKEY\n");
    return EVP_ERROR;
  }

  if (!digest_fp(fp, type, digest, &digest_length)) {
    fprintf(stderr, "evp_verify: message digest failed\n");
    return EVP_ERROR;
  }

  ctx = EVP_MD_CTX_create();

  ret = evp_verify_internal(evp, ctx, type, digest, digest_length, s);

  EVP_MD_CTX_cleanup(ctx);
  EVP_MD_CTX_destroy(ctx);

  return ret;
}
