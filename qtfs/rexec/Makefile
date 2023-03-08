DEPGLIB=-lglib-2.0 -I../ -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

all: rexec rexec_server

rexec :
	gcc -O2 -g -o rexec rexec.c rexec_sock.c cJSON.c

rexec_server :
	gcc -O2 -g -o rexec_server rexec_server.c rexec_sock.c rexec_shim.c cJSON.c $(DEPGLIB)
test:
	go test -v ./common_test.go ./common.go

install:
	yes | cp -f rexec /usr/bin/
	yes | cp -f rexec_server /usr/bin/

clean:
	rm -rf rexec rexec_server
