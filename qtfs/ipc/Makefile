all: udsproxyd libudsproxy.so

udsproxyd: uds_event.o uds_main.o
	gcc -g -O2 -o udsproxyd $^ -I../

libudsproxy.so:
	gcc -g -O2 -o libudsproxy.so uds_connector.c -fPIC --shared

clean:
	@rm -rf *.o udsproxyd libudsproxy.so

.PHONY: clean
