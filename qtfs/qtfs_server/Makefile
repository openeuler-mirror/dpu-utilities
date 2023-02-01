ccflags-y += -I$(src)/../ -I$(src) -DQTFS_SERVER
KBUILD=/lib/modules/$(shell uname -r)/build/

obj-m:=qtfs_server.o
qtfs_server-objs:=../conn.o fsops.o qtfs-server.o ../misc.o

all: qtfs_server engine

qtfs_server:
	make -C $(KBUILD) M=$(PWD) modules

engine: uds_event.o uds_main.o user_engine.o
	gcc -O2 -o engine $^ -lpthread -I../ -I../ipc/ -DQTFS_SERVER

user_engine.o:
	cc -g -c -o user_engine.o user_engine.c -I../ -DQTFS_SERVER

uds_event.o:
	cc -g -c -o uds_event.o ../ipc/uds_event.c -DQTFS_SERVER

uds_main.o:
	cc -g -c -o uds_main.o ../ipc/uds_main.c -DQTFS_SERVER

clean:
	make -C $(KBUILD) M=$(PWD) clean
	rm -rf engine
	rm -rf ../*.o
