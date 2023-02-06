all: udsproxyd libudsproxy.so

udsproxyd: uds_event.o uds_main.o
	gcc -g -O2 -o udsproxyd $^ -I../

uds_event.o:
	cc -g -c -o uds_event.o uds_event.c

uds_main.o:
	cc -g -c -o uds_main.o uds_main.c

libudsproxy.so:
	gcc -g -O2 -o libudsproxy.so uds_connector.c -fPIC --shared

install:
	yes | cp udsproxyd /usr/bin/
	yes | cp libudsproxy.so /usr/lib64/

clean:
	@rm -rf *.o udsproxyd libudsproxy.so
	
.PHONY: clean
