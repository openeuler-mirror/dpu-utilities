#ifndef __UDS_H__
#define __UDS_H__


int udsRecvFd(int sock, int fdflags);

int udsSendFd(int sock, int fd);

#endif