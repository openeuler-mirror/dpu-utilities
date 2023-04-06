ccflags-y += -I$(src)/../ -I$(src)/../utils/ -I$(src)/../include/ -I$(src)/../ipc/ -I$(src) -DQTFS_CLIENT
KBUILD=/lib/modules/$(shell uname -r)/build/
COMM=../qtfs_common/
COMMO=$(COMM)/conn.o $(COMM)/misc.o $(COMM)/symbol_wrapper.o $(COMM)/socket.o

obj-m:=qtfs.o
qtfs-objs:=qtfs-mod.o sb.o syscall.o xattr.o proc.o miss.o $(COMMO) ../utils/utils.o

all: qtfs

qtfs:
	make -C $(KBUILD) M=$(PWD) modules

clean:
	make -C $(KBUILD) M=$(PWD) clean
	rm -rf ../*.o ../.*.o.cmd
	rm -rf $(COMMO) $(COMM).*.o.cmd
	rm -rf ../utils/*.o ../utils/.*.o.cmd
