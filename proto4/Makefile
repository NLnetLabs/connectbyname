CFLAGS=-g 
LDFLAGS=
LIBS=-levent -levent_openssl -lssl

all:	get443_4

GET443_4_OBJ=get443.o connectbyname.o

get443_4: $(GET443_4_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(GET443_4_OBJ) $(LIBS)

clean:
	rm -f get443_4 $(GET443_4_OBJ)
