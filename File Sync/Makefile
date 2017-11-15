PORT=58915
CFLAGS = -DPORT=$(PORT) -g -Wall -std=gnu99
DEPENDENCIES = hash.h ftree.h

all: rcopy_server rcopy_client

rcopy_server: rcopy_server.o hash_functions.o ftree.o
	gcc ${CFLAGS} -o $@ $^

rcopy_client: rcopy_client.o hash_functions.o ftree.o
	gcc ${CFLAGS} -o $@ $^

%.o: %.c ${DEPENDENCIES}
	gcc ${CFLAGS} -c $<

clean:
	rm -f *.o rcopy_server rcopy_client
	
