
# tcpsplit
# Mark Allman (mallman@icir.org)

# Copyright (c) 2004--2013 International Computer Science Institute
# 
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# The names and trademarks of copyright holders may not be used in
# advertising or publicity pertaining to the software without specific
# prior permission. Title to copyright in this software and any
# associated documentation will at all times remain with the copyright
# holders.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

VERSION=0.3

CC=gcc
INC=-Ilib/include
CFLAGS=-g -Wall -Werror $(INC) $(OTHER)
LD=gcc
LDFLAGS=$(CFLAGS)
LIBS=-lpcap

OBJS=balancer.o ipa_db.o tcpsplit.o

all: tcpsplit 

## tcpsplit

tcpsplit: $(OBJS)
	$(CC) $(LDFLAGS) -o tcpsplit $(OBJS) $(LIBS)

balancer.o: balancer.c tcpsplit.h
	$(CC) $(CFLAGS) -c balancer.c

ipa_db.o: ipa_db.c tcpsplit.h
	$(CC) $(CFLAGS) -c ipa_db.c

tcpsplit.o: tcpsplit.c tcpsplit.h Makefile
	$(CC) $(CFLAGS) -c -DVERSION=\"$(VERSION)\" tcpsplit.c

## misc

tar:
	mkdir tcpsplit-$(VERSION)
	cp Makefile* COPYRIGHT README *.h *.c validate tcpsplit-$(VERSION)
	tar cvzf tcpsplit-$(VERSION).tar.gz tcpsplit-$(VERSION)/
	rm -rf tcpsplit-$(VERSION)

clean:
	rm -f *.o *core core 

distclean: clean
	rm -f tcpsplit
