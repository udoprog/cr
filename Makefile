CFLAGS_GLIB=$(shell pkg-config --cflags glib-2.0)
LDFLAGS_GLIB=$(shell pkg-config --libs glib-2.0)

CFLAGS_OPENSSL=$(shell pkg-config --cflags openssl)
LDFLAGS_OPENSSL=$(shell pkg-config --libs openssl)

CFLAGS=${CFLAGS_GLIB} ${CFLAGS_OPENSSL} -Wall -pedantic
LDFLAGS=${LDFLAGS_GLIB} ${LDFLAGS_OPENSSL}

SOURCES+=error.c
OBJECTS=${SOURCES:.c=.o}

all: privme

privme: ${OBJECTS}

clean:
	rm -f privme
	rm -f ${OBJECTS}
