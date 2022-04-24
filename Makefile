CC =gcc
CFLAGS =-Wall -g

# Just compile/link all files in one hit.
demo: sniffer.c
	${CC} ${CFLAGS} -o sniffer sniffer.c -lpcap

clean:
	rm -f demo
