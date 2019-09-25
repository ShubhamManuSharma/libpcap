IDIR=.
CC=gcc
CFLAGS=-I${IDIR}
DEPS =*.h
OBJ = main.o chksm.o
LDFLAGS=-lpcap

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

pcap: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PTHONY:clean

clean:
	rm -rf $(OBJ) main 
