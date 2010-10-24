#
# pcaplua: a libpcap binding
# (c) 2010 Javier Guerra G.
#

# Compilation parameters
CC = gcc
CWARNS = -Wall -pedantic \
        -Waggregate-return \
        -Wcast-align \
        -Wmissing-prototypes \
        -Wstrict-prototypes \
        -Wnested-externs \
        -Wpointer-arith \
        -Wshadow \
        -Wwrite-strings

CFLAGS = $(CONFIG) $(CWARNS) -std=gnu99 -g -O2 -I/usr/include/lua5.1 -fPIC
LDFLAGS = -lpcap

%.so: %.o
	ld $(LDFLAGS) -o $@ -shared $<


all : pcaplua.so

clean:
	rm *.o *.so core core.* a.out