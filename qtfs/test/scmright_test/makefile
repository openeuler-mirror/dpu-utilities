.PHONY: all

all: libscm.so client server

client: libscm.so client.c
        gcc client.c -L. -lscm -o client

server: libscm.so server.c
        gcc server.c -L. -lscm -o server

libscm.so: scm_rights.c
        gcc -fPIC --share scm_rights.c -o libscm.so

clean:
        rm -f client server libscm.so *.o