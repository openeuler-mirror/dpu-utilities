CFLAGS += -g -O2
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIE -pie -fPIC
CFLAGS += -D_FORTIFY_SOURCE=2
LDFLAGS += -s
LDFLAGS += -Wl,-z,now
LDFLAGS += -Wl,-z,noexecstack
LDFLAGS += -fPIE -pie

all: qtinfo qtcfg

qtinfo:
	gcc $(CFLAGS) $(LDFLAGS) -D$(role) -o qtinfo qtinfo.c -I../ -I../include/

qtcfg:
	gcc $(CFLAGS) $(LDFLAGS) -DQTINFO_RELEASE -D$(role) -o qtcfg qtinfo.c -I../ -I../include/

install:
	yes | cp qtinfo /usr/bin/
	yes | cp qtcfg /usr/bin/

clean:
	rm -rf qtcfg qtinfo qtinfo.o

