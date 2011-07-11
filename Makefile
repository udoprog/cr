CFLAGS_OPENSSL=$(shell pkg-config --cflags openssl)
LDFLAGS_OPENSSL=$(shell pkg-config --libs openssl)

CC=gcc
CFLAGS=${CFLAGS_OPENSSL} -Wall -pedantic -g
LDFLAGS=${LDFLAGS_OPENSSL}

SOURCES+=error.c
SOURCES+=base64.c
SOURCES+=cr.c
SOURCES+=rsa.c
OBJECTS=${SOURCES:.c=.o}

all: cr

cr: ${OBJECTS}
	${CC} ${CFLAGS} ${OBJECTS} ${LDFLAGS} -o $@

clean:
	rm -f cr
	rm -f ${OBJECTS}
