CFLAGS += -fgnu89-inline
LDLIBS += -lpcap
LDLIBS += -lnet

all: pcap-test

pcap-test: pcap-test.c

clean:
	rm -f pcap-test *.o
