DEPGLIB=-lglib-2.0 -I../ -I../include/ -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -lpthread
CFLAGS += -g -O2
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIE -pie -fPIC
CFLAGS += -D_FORTIFY_SOURCE=2
ifdef UDS_TEST_MODE
CFLAGS += -DUDS_TEST_MODE
endif
LDFLAGS += -s
LDFLAGS += -Wl,-z,now
LDFLAGS += -Wl,-z,noexecstack
LDFLAGS += -fPIE -pie

all: udsproxyd libudsproxy.so

udsproxyd: uds_event.o uds_main.o
	gcc $(LDFLAGS) -o udsproxyd $^ -I../ $(DEPGLIB)
	@test -z $(UDS_TEST_MODE) || echo "Important risk warning: The test mode is turned on,\
	and udsproxyd will expose the network port, which will bring security risks and is only for\
	testing! If you do not understand the risks, please don't use or compile again without\
	UDS_TEST_MODE."

uds_event.o:
	cc $(CFLAGS) -c -o uds_event.o uds_event.c $(DEPGLIB)

uds_main.o:
	cc $(CFLAGS) -c -o uds_main.o uds_main.c $(DEPGLIB)

libudsproxy.so:
	gcc $(CFLAGS) $(LDFLAGS) -o libudsproxy.so uds_connector.c --shared

install:
	yes | cp udsproxyd /usr/bin/
	yes | cp libudsproxy.so /usr/lib64/

clean:
	@rm -rf *.o udsproxyd libudsproxy.so
	
.PHONY: clean
