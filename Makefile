CFLAGS_OPENSSL=$(shell pkg-config --cflags libcrypto)
LDFLAGS_OPENSSL=$(shell pkg-config --libs libcrypto)

CC=gcc
CFLAGS=${CFLAGS_OPENSSL} -Wall -pedantic -g
LDFLAGS=${LDFLAGS_OPENSSL}

SOURCES+=src/error.c
SOURCES+=src/base64.c
SOURCES+=src/cr.c
SOURCES+=src/evp.c
SOURCES+=src/str.c
OBJECTS=${SOURCES:.c=.o}

all: cr

cr: ${OBJECTS}
	${CC} ${CFLAGS} ${OBJECTS} ${LDFLAGS} -o $@

clean:
	rm -f cr
	rm -f ${OBJECTS}
