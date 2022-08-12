
all: qtinfo

qtinfo:
	gcc -g -O2 -D$(role) -o qtinfo qtinfo.c -I../

install:
	cp qtinfo /usr/bin/

clean:
	rm -rf qtinfo qtinfo.o

