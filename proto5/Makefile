LIBEVENT=/home/philip/src/libevent-2.1.11-stable

CFLAGS=-g -I$(LIBEVENT)/include
LDFLAGS=-static -g -L$(LIBEVENT)/.libs
LDFLAGS=-g -L$(LIBEVENT)/.libs
LIBS=-levent -levent_openssl -lssl /usr/lib/x86_64-linux-gnu/libgetdns_ex_event.a -L /home/philip/src/getdns-1.7.0 -Wl,-rpath=/home/philip/src/getdns-1.7.0 -lgetdns


all:	get443_5

GET443_5_OBJ=get443.o connectbyname.o

get443_5: $(GET443_5_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(GET443_5_OBJ) $(LIBS)

clean:
	rm -f get443_5 $(GET443_5_OBJ)
