######################################### VERY SIMPLE MAKE FILE NEED CHANGES ####################################################

#sniffer: build/main.c build/sniffer.c protocols/tcp.c protocols/udp.c protocols/icmp.c
#	gcc build/main.c build/sniffer.c protocols/tcp.c protocols/udp.c protocols/icmp.c && sudo ./a.out

IDIR =../headers
CC=gcc
CFLAGS=-I$(IDIR)

CFLAGS += $(shell pkg-config --cflags json-c)
LDFLAGS += $(shell pkg-config --libs json-c)

ODIR=build
PDIR=protocols
LDIR =../include

LIBS=-lm

_DEPS = sniffer.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = main.o sniffer.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

_PRO = icmp.o tcp.o udp.o
PRO = $(patsubst %,$(PDIR)/%,$(_PRO))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(PDIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

sniffer: $(OBJ) $(PRO)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) && sudo ./sniffer

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 
	rm -f $(PDIR)/*.o *~ core $(INCDIR)/*~ 

