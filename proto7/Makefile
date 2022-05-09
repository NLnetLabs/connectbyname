LIBGETDNS=/home/philip/src/getdns/libgetdns.a /home/philip/src/getdns/libgetdns_ext_event.a -lunbound -lidn2
LIBLDNS=-lldns
LIBSSL=-lssl -lcrypto

CFLAGS=-g
LDFLAGS=-g
LIBS=-levent -levent_openssl $(LIBGETDNS) $(LIBLDNS) $(LIBSSL)


all:	get443_7

GET443_7_OBJ=get443.o connectbyname.o

connectbyname.o: connectbyname.h
get443.o: connectbyname.h

get443_7: $(GET443_7_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(GET443_7_OBJ) $(LIBS)

clean:
	rm -f get443_7 $(GET443_7_OBJ)
