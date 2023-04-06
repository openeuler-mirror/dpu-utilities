ccflags-y += -I$(src)/../ -I$(src) -I$(src)/../ipc/ -I$(src)/../include/ -DQTFS_SERVER
KBUILD=/lib/modules/$(shell uname -r)/build/
COMM=../qtfs_common/
COMMO=$(COMM)/conn.o $(COMM)/misc.o $(COMM)/symbol_wrapper.o $(COMM)/socket.o

obj-m:=qtfs_server.o
qtfs_server-objs:=fsops.o qtfs-server.o $(COMMO)

DEPGLIB=-lglib-2.0 -I../ -I../include/ -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

all: qtfs_server engine

qtfs_server:
	make -C $(KBUILD) M=$(PWD) modules

engine: uds_event.o uds_main.o user_engine.o
	gcc -O2 -o engine $^ -lpthread $(DEPGLIB) -I../ -I../ipc/ -DQTFS_SERVER

user_engine.o:
	cc -g -c -o user_engine.o ../qtfs_common/user_engine.c $(DEPGLIB) -I../ -DQTFS_SERVER

uds_event.o:
	cc -g -c -o uds_event.o ../ipc/uds_event.c -DQTFS_SERVER $(DEPGLIB)

uds_main.o:
	cc -g -c -o uds_main.o ../ipc/uds_main.c -DQTFS_SERVER $(DEPGLIB)

clean:
	make -C $(KBUILD) M=$(PWD) clean
	rm -rf engine
	rm -rf ../*.o
	rm -rf $(COMMO) $(COMM).*.o.cmd
