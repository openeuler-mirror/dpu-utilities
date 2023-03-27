
all: qtinfo qtcfg

qtinfo:
	gcc -g -O2 -D$(role) -o qtinfo qtinfo.c -I../ -I../include/

qtcfg:
	gcc -g -O2 -DQTINFO_RELEASE -D$(role) -o qtcfg qtinfo.c -I../ -I../include/

install:
	yes | cp qtinfo /usr/bin/
	yes | cp qtcfg /usr/bin/

clean:
	rm -rf qtcfg qtinfo qtinfo.o

