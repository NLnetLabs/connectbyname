LIBEVENT=/home/philip/src/libevent-2.1.11-stable

CFLAGS=-g -I$(LIBEVENT)/include
LDFLAGS=-static -g -L$(LIBEVENT)/.libs
LDFLAGS=-g -L$(LIBEVENT)/.libs
LIBS=-levent #-levent_pthreads -lpthread


all:	get80_3

GET80_3_OBJ=get80.o connectbyname.o

get80_3: $(GET80_3_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(GET80_3_OBJ) $(LIBS)

clean:
	rm -f get80_3 $(GET80_3_OBJ)
