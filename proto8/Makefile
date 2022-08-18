LIBGETDNS=/home/philip/src/getdns/libgetdns.a /home/philip/src/getdns/libgetdns_ext_event.a -lunbound -lidn2
LIBLDNS=-lldns
LIBSSL=-lssl -lcrypto

CFLAGS=-g -I/home/philip/src/getdns
LDFLAGS=-g
LIBS=-levent -levent_openssl $(LIBGETDNS) $(LIBLDNS) $(LIBSSL)


all:	get443_8

GET443_8_OBJ=get443.o connectbyname.o

connectbyname.o: connectbyname.h
get443.o: connectbyname.h

get443_8: $(GET443_8_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(GET443_8_OBJ) $(LIBS)

clean:
	rm -f get443_8 $(GET443_8_OBJ)
