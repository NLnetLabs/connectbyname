# This code relies on experimental code that lives in the branch
# 'philip-proxy-config' in the getdns repository.

# Set the GETDNSSRC variable to the directory where getdns is checked out and
# compiled
GETDNSSRC=../../getdns
LDNSSRC=../../ldns

LIBGETDNS=$(GETDNSSRC)/libgetdns.a $(GETDNSSRC)/libgetdns_ext_event.a -lunbound -lidn2
LIBLDNS=$(LDNSSRC)/.libs/libldns.a
LIBSSL=-lssl -lcrypto

CFLAGS=-g -I$(GETDNSSRC) -I$(LDNSSRC)
LDFLAGS=-g
LIBS=-levent -levent_openssl $(LIBGETDNS) $(LIBLDNS) $(LIBSSL)


all:	get443_9

GET443_9_OBJ=get443.o connectbyname.o

connectbyname.o: connectbyname.h
get443.o: connectbyname.h

get443_9: $(GET443_9_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(GET443_9_OBJ) $(LIBS)

clean:
	rm -f get443_9 $(GET443_9_OBJ)
