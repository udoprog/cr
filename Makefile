CFLAGS_OPENSSL=$(shell pkg-config --cflags libcrypto)
LDFLAGS_OPENSSL=$(shell pkg-config --libs libcrypto)

CC=gcc
CFLAGS=${CFLAGS_OPENSSL} -Wall -pedantic -g
LDFLAGS=${LDFLAGS_OPENSSL}

SOURCES+=error.c
SOURCES+=base64.c
SOURCES+=cr.c
SOURCES+=evp.c
SOURCES+=string.c
OBJECTS=${SOURCES:.c=.o}

all: cr

cr: ${OBJECTS}
	${CC} ${CFLAGS} ${OBJECTS} ${LDFLAGS} -o $@

clean:
	rm -f cr
	rm -f ${OBJECTS}
