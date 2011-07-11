#include "base64.h"
#include "error.h"
#include "bool.h"

#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

int base64_fencode(FILE* fp, const unsigned char* source, int size)
{
  BIO *bio;
  BIO *b64;

  b64 = BIO_new(BIO_f_base64());

  if (b64 == NULL) {
    error_all_print("BIO_new");
    goto exit_error;
  }

  bio = BIO_new_fp(fp, BIO_NOCLOSE);

  if (bio == NULL) {
    error_all_print("BIO_new_fp");
    goto exit_error;
  }

  bio = BIO_push(b64, bio);

  if (BIO_write(bio, source, size) <= 0) {
    error_all_print("BIO_write");
    goto exit_error;
  }

  BIO_flush(bio);
  BIO_free_all(bio);
  return TRUE;

exit_error:
  if (bio != NULL) {
    BIO_free_all(bio);
    b64 = NULL;
  }

  if (b64 != NULL) {
    BIO_free(b64);
  }

  return FALSE;
}

int base64_fdecode(FILE* fp, unsigned char** out, int* size)
{
  BIO *bio = NULL;
  BIO *b64 = NULL;

  int inlen = 0;
  int pos = 0;
  int c = BASE64_INITIAL_BUFFER;
  unsigned char* tmp = NULL;
  unsigned char* rtmp = NULL;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(fp, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);

  tmp = malloc(c);

  memset(tmp, 0x00, c);

  if (tmp == NULL) {
    error_all_print("malloc");
    return FALSE;
  }

  while((inlen = BIO_read(bio, tmp + pos, c - pos)) > 0) {
    pos += inlen;

    if (pos >= c) {
      c *= 2;
      rtmp = realloc(tmp, c);

      if (rtmp == NULL) {
        error_all_print("realloc");
        goto exit_error;
      }

      memset(rtmp + pos, 0x00, c - pos);
      
      tmp = rtmp;
      rtmp = NULL;
    }
  }

  *size = pos;

  BIO_free_all(bio);

  *out = tmp;

  return TRUE;

exit_error:
  if (tmp != NULL) {
    free(tmp);
  }

  return FALSE;
}

