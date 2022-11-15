# This code relies on experimental code that lives in the branch
# 'philip-proxy-config' in the getdns repository.

# Set the GETDNSSRC variable to the directory where getdns is checked out and
# compiled
GETDNSSRC=../../getdns
LDNSSRC=../../ldns
OPENSSLSRC=/home/philip/src/sftcd-openssl
LIBEVENTSRC=/home/philip/src/libevent-2.1.12-stable
UNBOUNDSRC=/home/philip/src/unbound

LIBLDNS=$(LDNSSRC)/.libs/libldns.a
LIBSSL=$(OPENSSLSRC)/libssl.a $(OPENSSLSRC)/libcrypto.a
LIBEVENT=$(LIBEVENTSRC)/.libs/libevent.a $(LIBEVENTSRC)/.libs/libevent_openssl.a
LIBUNBOUND=-Wl,-rpath ${UNBOUNDSRC}/.libs $(UNBOUNDSRC)/.libs/libunbound.so
#LIBUNBOUND=$(UNBOUNDSRC)/.libs/libunbound.a
LIBGETDNS=$(GETDNSSRC)/libgetdns.a $(GETDNSSRC)/libgetdns_ext_event.a -lidn2

CFLAGS=-g -I$(GETDNSSRC) -I$(LDNSSRC) -I$(OPENSSLSRC)/include
LDFLAGS=-g
LIBS=$(LIBGETDNS) $(LIBEVENT) $(LIBLDNS) $(LIBSSL) $(LIBUNBOUND)


all:	get443_10

GET443_10_OBJ=get443.o connectbyname.o

connectbyname.o: connectbyname.h
get443.o: connectbyname.h

get443_10: $(GET443_10_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(GET443_10_OBJ) $(LIBS)

clean:
	rm -f get443_10 $(GET443_10_OBJ)
