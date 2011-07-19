/*
 * Copyright (c) 2011, John-John Tedro <johnjohn.tedro@toolchain.eu>
 * All rights reserved.
 * see LICENSE
 */
#include "str.h"
#include "base64.h"
#include "error.h"
#include "bool.h"

#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

int base64_fencode(FILE* fp, string* s)
{
  BIO *bio = NULL;
  BIO *b64 = NULL;

  b64 = BIO_new(BIO_f_base64());

  if (b64 == NULL) {
    return FALSE;
  }

  bio = BIO_new_fp(fp, BIO_NOCLOSE);

  if (bio == NULL) {
    BIO_free(b64);
    return FALSE;
  }

  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  if (BIO_write(bio, string_base(s), string_size(s)) <= 0) {
    goto error;
  }

  if (!BIO_flush(bio)) {
    goto error;
  }

  BIO_free_all(bio);
  return TRUE;
error:
  BIO_free_all(bio);
  return FALSE;
}

int base64_fdecode(FILE* fp, string* s)
{
  BIO *bio = NULL;
  BIO *b64 = NULL;

  unsigned char buffer[4096];
  int inlen;

  b64 = BIO_new(BIO_f_base64());

  if (b64 == NULL) {
    return FALSE;
  }

  bio = BIO_new_fp(fp, BIO_NOCLOSE);

  if (bio == NULL) {
    BIO_free(b64);
    return FALSE;
  }

  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  while((inlen = BIO_read(bio, buffer, 4096)) > 0) {
    if (string_append(s, buffer, inlen) == 0) {
      BIO_free_all(bio);
      return FALSE;
    }
  }

  BIO_free_all(bio);
  return TRUE;
}
