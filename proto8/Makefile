# This code relies on experimental code that lives in the branch
# 'philip-proxy-config' in the getdns repository.

# Set the GETDNSSRC variable to the directory where getdns is checked out and
# compiled
GETDNSSRC=../../getdns

LIBGETDNS=$(GETDNSSRC)/libgetdns.a $(GETDNSSRC)/libgetdns_ext_event.a -lunbound -lidn2
LIBLDNS=-lldns
LIBSSL=-lssl -lcrypto

CFLAGS=-g -I$(GETDNSSRC)
LDFLAGS=-g
LIBS=-levent -levent_openssl $(LIBGETDNS) $(LIBLDNS) $(LIBSSL)


all:	get443_8

GET443_8_OBJ=get443.o connectbyname.o

connectbyname.o: connectbyname.h
get443.o: connectbyname.h

get443_8: $(GET443_8_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(GET443_8_OBJ) $(LIBS)

doxygen:
	if test ! -e doc/header.html ; then \
		mkdir -p doc; \
		cp ../etc/header.html doc; \
	fi ;
	doxygen config.doxygen

doc:	doxygen

clean:
	rm -f get443_8 $(GET443_8_OBJ)
	rm -rf doc
