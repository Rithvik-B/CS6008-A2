# Phase 2 interceptor build. Requires libpcap-dev (present in the lab base image).
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDLIBS  := -lpcap

interceptor: interceptor.c
	$(CC) $(CFLAGS) -o $@ interceptor.c $(LDLIBS)

clean:
	rm -f interceptor

.PHONY: clean
