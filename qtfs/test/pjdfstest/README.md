# 开源文件系统测试集pjdfstest

pjdfstest是一个POSIX系统接口的测试套，用于进行文件系统接口兼容性测试，相关说明及源码可见其开源链接：

[pjdfstest](https://github.com/pjd/pjdfstest)

### 部署

```bash
# qtfs仍有部分接口兼容未实现，所以pjdfstest用例进行部分裁剪，请使用下述源码进行验证
$ git clone https://gitee.com/anar/pjdfstest.git

$ cd pjdfstest

# pjdfstest源码编译，生成prove二进制
$ autoreconf-ifs

$ ./configure

$ make pjdfstest

```

### 测试

* 进入挂载qtfs文件系统的目录

* 执行prove -rv ${pjdfstest文件所在目录}

根据执行结果确定测试是否通过。
