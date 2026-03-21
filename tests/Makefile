CC      ?= gcc
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -Werror -I../include -I.
SRC     := ../src/mcrypt.c

.PHONY: all clean

all: test_all
	./test_all

test_all: test_all.c mtest.h $(SRC) ../include/mcrypt.h
	$(CC) $(CFLAGS) $(SRC) test_all.c -lm -o $@

clean:
	rm -f test_all test_all.exe
