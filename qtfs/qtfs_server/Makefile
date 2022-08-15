ccflags-y += -I$(src)/../ -I$(src) -DQTFS_SERVER
KBUILD=/lib/modules/5.10*/build/

obj-m:=qtfs_server.o
qtfs_server-objs:=../conn.o fsops.o qtfs-server.o ../misc.o

all: qtfs_server engine

qtfs_server:
	make -C $(KBUILD) M=$(PWD) modules

engine:
	gcc -O2 -o engine user_engine.c -lpthread -I../ -DQTFS_SERVER

clean:
	make -C $(KBUILD) M=$(PWD) clean
	rm -rf engine
	rm -rf ../*.o
