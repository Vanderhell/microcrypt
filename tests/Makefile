CC      ?= gcc
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
OPENSSL_DEFS :=
ifneq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_DEFS := -DMICROCRYPT_HAVE_OPENSSL=1
endif
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -Werror -I../include -I. $(OPENSSL_CFLAGS)
SRC     := ../src/mcrypt.c

.PHONY: all clean

all: test_all
	./test_all

test_all: test_all.c mtest.h $(SRC) ../include/mcrypt.h
	$(CC) $(CFLAGS) $(SRC) test_all.c -lm $(OPENSSL_LIBS) $(OPENSSL_DEFS) -o $@

clean:
	rm -f test_all test_all.exe
