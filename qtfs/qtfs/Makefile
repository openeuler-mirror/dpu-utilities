ifdef QTFS_TEST_MODE
ccflags-y += -I$(src)/../ -I$(src)/../utils/ -I$(src)/../include/ -I$(src)/../ipc/ -I$(src) -DQTFS_CLIENT -DQTFS_TEST_MODE
else
ccflags-y += -I$(src)/../ -I$(src)/../utils/ -I$(src)/../include/ -I$(src)/../ipc/ -I$(src) -DQTFS_CLIENT
endif

KBUILD=/lib/modules/$(shell uname -r)/build/
COMM=../qtfs_common/
COMMO=$(COMM)/conn.o $(COMM)/misc.o $(COMM)/symbol_wrapper.o $(COMM)/socket.o

obj-m:=qtfs.o
qtfs-objs:=qtfs-mod.o sb.o syscall.o xattr.o proc.o miss.o $(COMMO) ../utils/utils.o

all: qtfs

qtfs:
	make -C $(KBUILD) M=$(PWD) modules
	@test -z $(QTFS_TEST_MODE) || echo "Important risk warning: The test mode is turned on,\
	and qtfs will expose the network port, which will bring security risks and is only for\
	testing! If you do not understand the risks, please don't use or compile again without\
	QTFS_TEST_MODE."

clean:
	make -C $(KBUILD) M=$(PWD) clean
	rm -rf ../*.o ../.*.o.cmd
	rm -rf $(COMMO) $(COMM).*.o.cmd
	rm -rf ../utils/*.o ../utils/.*.o.cmd
