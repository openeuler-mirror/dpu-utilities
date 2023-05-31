DEPGLIB=-lglib-2.0 -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

CFLAGS += -g -O2
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIE -pie -fPIC
CFLAGS += -D_FORTIFY_SOURCE=2
LDFLAGS += -s
LDFLAGS += -Wl,-z,now
LDFLAGS += -Wl,-z,noexecstack
LDFLAGS += -fPIE -pie

all: rexec rexec_server

rexec :
	gcc $(CFLAGS) $(LDFLAGS) -o rexec rexec.c rexec_sock.c -ljson-c

rexec_server :
	gcc $(CFLAGS) $(LDFLAGS) -o rexec_server rexec_server.c rexec_sock.c rexec_shim.c -ljson-c $(DEPGLIB)
test:
	go test -v ./common_test.go ./common.go

install:
	yes | cp -f rexec /usr/bin/
	yes | cp -f rexec_server /usr/bin/

clean:
	rm -rf rexec rexec_server
