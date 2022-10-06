# getdns is broken on debian and ubuntu. Use a local src

# Set the GETDNSSRC variable to the directory where getdns is checked out and
# compiled
GETDNSSRC=../../getdns

LIBGETDNS=$(GETDNSSRC)/libgetdns.a $(GETDNSSRC)/libgetdns_ext_event.a -lunbound -lidn2
LIBLDNS=-lldns
LIBSSL=-lssl -lcrypto

CFLAGS=-g -I$(GETDNSSRC)
LDFLAGS=-g
LIBS=-levent -levent_openssl $(LIBGETDNS) $(LIBLDNS) $(LIBSSL)

all:	get443_5

GET443_5_OBJ=get443.o connectbyname.o

get443_5: $(GET443_5_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(GET443_5_OBJ) $(LIBS)

clean:
	rm -f get443_5 $(GET443_5_OBJ)
