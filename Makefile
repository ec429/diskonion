# Makefile for diskonion, a layered deniable disk encryption scheme

CC := gcc
CFLAGS := -Wall -Wextra -Werror -pedantic --std=gnu99 -g
#CPPFLAGS := -DINSUFFICIENTLY_PARANOID # this is temporary, for debugging/development
FUSE := `pkg-config fuse --cflags` -Wno-unused
LDFUSE := `pkg-config fuse --libs`
LDCRYPTO := -lssl

all: mkonion onionmount

onionmount: onionmount.c crypto.o crypto.h onion.o onion.h bits.o bits.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(FUSE) onionmount.c $(LDFLAGS) crypto.o onion.o bits.o $(LDFUSE) $(LDCRYPTO) -o $@

mkonion: mkonion.c crypto.o crypto.h onion.o onion.h bits.o bits.h
	$(CC) $(CFLAGS) $(CPPFLAGS) mkonion.c $(LDFLAGS) crypto.o onion.o bits.o $(LDCRYPTO) -o $@

crypto.o: bits.h

%.o: %.c %.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

