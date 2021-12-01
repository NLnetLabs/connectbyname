all:	get80_1

GET80_1_OBJ=get80.o connectbyname.o

get80_1: $(GET80_1_OBJ)
	$(CC) -o $@ $(GET80_1_OBJ)

clean:
	rm -f get80_1 $(GET80_1_OBJ)
