LIBEVENT=/home/philip/src/libevent-2.1.11-stable

CFLAGS=-g -I$(LIBEVENT)/include
LDFLAGS=-static -g -L$(LIBEVENT)/.libs
LDFLAGS=-g -L$(LIBEVENT)/.libs
LIBS=-levent -levent_openssl -lssl /usr/lib/x86_64-linux-gnu/libgetdns_ex_event.a -L /home/philip/src/getdns -Wl,-rpath=/home/philip/src/getdns -lgetdns /home/philip/src/ldns/.libs/libldns.a -lcrypto


all:	get443_6

GET443_6_OBJ=get443.o connectbyname.o

get443_6: $(GET443_6_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(GET443_6_OBJ) $(LIBS)

clean:
	rm -f get443_6 $(GET443_6_OBJ)
