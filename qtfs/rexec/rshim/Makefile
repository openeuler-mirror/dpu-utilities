all: rexec_shim

rexec_shim:
	gcc -g -O2 -o rexec_shim rexec_shim.c cJSON.c

install:
	cp rexec_shim /usr/bin/

clean:
	rm -rf rexec_shim *.o
