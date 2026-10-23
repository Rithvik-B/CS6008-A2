# Phase 5 zone-walker. Requires libpcap-dev (present in the lab base image).
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDLIBS  := -lpcap

zonewalk: zonewalk.c
	$(CC) $(CFLAGS) -o $@ zonewalk.c $(LDLIBS)

clean:
	rm -f zonewalk
.PHONY: clean
