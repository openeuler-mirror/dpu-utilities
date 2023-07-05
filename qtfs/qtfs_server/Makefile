ifdef QTFS_TEST_MODE
ccflags-y += -I$(src)/../ -I$(src) -I$(src)/../ipc/ -I$(src)/../include/ -DQTFS_SERVER -DQTFS_TEST_MODE
CFLAGS += -DUDS_TEST_MODE
else
ccflags-y += -I$(src)/../ -I$(src) -I$(src)/../ipc/ -I$(src)/../include/ -DQTFS_SERVER
endif

CFLAGS += -g -O2
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIE -pie -fPIC
CFLAGS += -D_FORTIFY_SOURCE=2
LDFLAGS += -Wl,-z,now
LDFLAGS += -Wl,-z,noexecstack
LDFLAGS += -fPIE -pie

KBUILD=/lib/modules/$(shell uname -r)/build/
COMM=../qtfs_common/
COMMO=$(COMM)/conn.o $(COMM)/misc.o $(COMM)/symbol_wrapper.o $(COMM)/socket.o

obj-m:=qtfs_server.o
qtfs_server-objs:=fsops.o qtfs-server.o $(COMMO)

DEPGLIB=-lglib-2.0 -I../ -I../include/ -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

all: qtfs_server engine

qtfs_server:
	make -C $(KBUILD) M=$(PWD) modules
	@test -z $(QTFS_TEST_MODE) || echo "Important risk warning: The test mode is turned on,\
	and qtfs will expose the network port, which will bring security risks and is only for\
	testing! If you do not understand the risks, please don't use or compile again without\
	QTFS_TEST_MODE."

engine: uds_event.o uds_main.o user_engine.o
	gcc $(LDFLAGS) -o engine $^ -lpthread $(DEPGLIB) -I../ -I../ipc/ -DQTFS_SERVER

user_engine.o:
	cc $(CFLAGS) -c -o user_engine.o ../qtfs_common/user_engine.c $(DEPGLIB) -I../ -DQTFS_SERVER

uds_event.o:
	cc $(CFLAGS) -c -o uds_event.o ../ipc/uds_event.c -DQTFS_SERVER $(DEPGLIB)

uds_main.o:
	cc $(CFLAGS) -c -o uds_main.o ../ipc/uds_main.c -DQTFS_SERVER $(DEPGLIB)

clean:
	make -C $(KBUILD) M=$(PWD) clean
	rm -rf engine
	rm -rf ../*.o
	rm -rf $(COMMO) $(COMM).*.o.cmd
