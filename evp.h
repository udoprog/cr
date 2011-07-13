#ifndef _EVP_H_
#define _EVP_H_

#include <openssl/evp.h>

#define EVP_IO_BUFFER_SIZE 4096

#define EVP_SHA1 1
#define EVP_MD5  2

#define EVP_SUCCESS 1
#define EVP_FAILURE 0
#define EVP_ERROR -1

typedef int (*password_callback) (const char* path, char* buf, int size);

typedef struct {
  const char* path;
  password_callback callback;
} password_request;

enum EVP_DIGEST_TYPE {
  evp_none = -1,
  evp_sha1 = 0,
  evp_md5  = 1
};

extern const char* EVP_DIGEST_TYPE_NAMES[];
extern const int EVP_DIGEST_TYPE_SIZES[];
extern const int EVP_DIGEST_TYPE_COUNT;

int evp_open_private(EVP_PKEY*, const char* path, password_callback callback);
int evp_open_public(EVP_PKEY*, const char* path, password_callback callback);

int sha1_digest_fp(FILE* fp, unsigned char* digest);
int evp_sign(EVP_PKEY*, enum EVP_DIGEST_TYPE, FILE*, string*);
int evp_verify(EVP_PKEY*, enum EVP_DIGEST_TYPE, FILE*, string*);

#endif /* _EVP_H_ */
