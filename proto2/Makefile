CFLAGS=-g
LDFLAGS=-g

all:	get80_2

GET80_2_OBJ=get80.o connectbyname.o

get80_2: $(GET80_2_OBJ)
	$(CC) -o $@ $(GET80_2_OBJ)

clean:
	rm -f get80_2 $(GET80_2_OBJ)
