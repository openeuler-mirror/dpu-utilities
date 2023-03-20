DEPGLIB=-lglib-2.0 -I../ -I../include/ -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

all: udsproxyd libudsproxy.so

udsproxyd: uds_event.o uds_main.o
	gcc -g -O2 -o udsproxyd $^ -I../ $(DEPGLIB)

uds_event.o:
	cc -g -c -o uds_event.o uds_event.c $(DEPGLIB)

uds_main.o:
	cc -g -c -o uds_main.o uds_main.c $(DEPGLIB)

libudsproxy.so:
	gcc -g -O2 -o libudsproxy.so uds_connector.c -fPIC --shared

install:
	yes | cp udsproxyd /usr/bin/
	yes | cp libudsproxy.so /usr/lib64/

clean:
	@rm -rf *.o udsproxyd libudsproxy.so
	
.PHONY: clean
