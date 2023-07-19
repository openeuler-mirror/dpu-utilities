# qtfs

## 介绍

qtfs是一个共享文件系统项目，可部署在host-dpu的硬件架构上，也可以部署在host-vm或同一台host的vm-vm之间，通过vsock建立安全通信通道。以客户端服务器的模式工作，使客户端能通过qtfs访问服务端的指定文件系统，就像访问本地文件系统一样。

qtfs的特性：
+ 支持挂载点传播；
+ 支持proc、sys、cgroup等特殊文件系统的共享；
+ 客户端对qtfs目录下文件的操作都被转移到服务端，文件读写可共享；
+ 支持在客户端对服务端的文件系统进行远程挂载；
+ 可以定制化处理特殊文件；
+ 支持远端fifo、unix-socket等，并且支持epoll，使客户端和服务端像本地通信一样使用这些文件；
+ 基于host-dpu架构时，底层通信方式可以支持PCIe，性能大大优于网络；
+ 内核模块形式开发，无需对内核进行侵入式修改。

## 软件架构

软件大体框架图：

![输入图片说明](doc/%20Overall_architecture_diagram.png)


## 安装教程

目录说明：
+ **rexec**：跨主机二进制生命周期管理组件，在该目录下编译rexec和rexec_server。
+ **ipc**: 跨主机unix domain socket协同组件，在该目录下编译udsproxyd二进制和libudsproxy.so库。
+ **qtfs**: 客户端内核模块相关代码，直接在该目录下编译客户端ko。
+ **qtfs_server**: 服务端内核模块相关代码，直接在该目录下编译服务端ko和相关程序。
+ **qtinfo**: 诊断工具，支持查询文件系统的工作状态以及修改log级别等。
+ **demo**、**test**、**doc**: 测试程序、演示程序以及项目资料等。
+ 根目录: 是客户端与服务端都能用到的公共模块代码。

### VSOCK通信模式

选择host-vm或同一台host上的vm-vm作为qtfs的client与server进行测试，通信通道为vsock：

	1. 启动vm时为vm配置vsock通道，vm可参考如下配置，将vsock段加在devices配置内：
```
	<devices>
	  ...
	  <vsock model='virtio'>
	    <cid auto='no' address='10'/>
	    <alias name='vsock0'/>
	    <address type='pci' domain='0x0000' bus='0x05' slot='0x00' function='0x0'/>
	  </vsock>
	  ...
    </devices>
```
	2. 要求内核版本在5.10或更高版本。
    3. 安装内核开发包：yum install kernel-devel。

服务端安装：

	1. cd qtfs_server
    2. make clean && make -j
    3. insmod qtfs_server.ko qtfs_server_vsock_cid=2 qtfs_server_vsock_port=12345 qtfs_log_level=WARN
	4. 配置白名单，将qtfs/config/qtfs/whitelist文件拷贝至/etc/qtfs/下，请手动配置需要的白名单选项，至少需要配置一个Mount白名单才能启动后续服务。
	5. nohup ./engine 16 1 2 12121 10 12121 2>&1 &
	Tips: 这里的cid需要根据配置决定，如果host作为server端，则cid固定配置为2，如果vm作为server端，则需要配置为前面xml中的cid字段，本例中为10。

客户端安装：
    
    1. cd qtfs
    2. make clean && make -j
    3. insmod qtfs.ko qtfs_server_vsock_cid=2 qtfs_server_vsock_port=12345 qtfs_log_level=WARN
	4. cd ../ipc/
	5. make clean && make && make install
	6. nohup udsproxyd 1 10 12121 2 12121 2>&1 &
	Tips：这里插入ko的cid和port配置为与server端一致即可，udsproxyd的cid+port与server端交换位置。

其他注意事项：
	
	1. udsproxyd目前也支持vsock和测试模式两种，使用vsock模式时，不能带UDS_TEST_MODE=1进行编译。
	2. 如果vsock不通，需要检查host是否插入了vhost_vsock内核模块：modprobe vhost_vsock。

### 测试模式，仅用于测试环境：

找两台服务器（或虚拟机）配置内核编译环境：

    1. 要求内核版本在5.10或更高版本。
    2. 安装内核开发包：yum install kernel-devel。
	3. 假设host服务器ip为192.168.10.10，dpu为192.168.10.11

服务端安装：
    
    1. cd qtfs_server
    2. make clean && make -j QTFS_TEST_MODE=1
    3. insmod qtfs_server.ko qtfs_server_ip=x.x.x.x qtfs_server_port=12345 qtfs_log_level=WARN
    4. 配置白名单，将qtfs/config/qtfs/whitelist文件拷贝至/etc/qtfs/下，请手动配置需要的白名单选项，至少需要配置一个Mount白名单才能启动后续服务。
    5. nohup ./engine 16 1 192.168.10.10 12121 192.168.10.11 12121 2>&1 &
    Tips: 该模式暴露网络端口，有可能造成安全隐患，仅能用于功能验证测试，勿用于实际生产环境。

客户端安装：
    
    1. cd qtfs
    2. make clean && make -j QTFS_TEST_MODE=1
    3. insmod qtfs.ko qtfs_server_ip=x.x.x.x qtfs_server_port=12345 qtfs_log_level=WARN
	4. cd ../ipc/
	5. make clean && make && make install
	6. nohup udsproxyd 1 192.168.10.11 12121 192.168.10.10 12121 2>&1 &
	Tips: 该模式暴露网络端口，有可能造成安全隐患，仅能用于功能验证测试，勿用于实际生产环境。

## 使用说明

安装完成后，客户端通过挂载把服务端的文件系统让客户端可见，例如：
    
    mount -t qtfs /home /root/mnt/

客户端进入"/root/mnt"后便可查看到server端/home目录下的所有文件，以及对其进行相关操作。此操作受到白名单的控制，需要挂载路径在server端白名单的Mount列表，或者在其子目录下，且后续的查看或读写操作都需要开放对应的白名单项才能进行。

## 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request
