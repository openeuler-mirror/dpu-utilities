#ifndef __QTFS_UTILS_H__
#define __QTFS_UTILS_H__

#define QTFS_UTILS_DEV "/dev/qtfs_utils"

// QTFS provide some remote capability
#define QTUTIL_IOCTL_CAPA_MAGIC 'U'
enum {
	_QTUTIL_IOCTL_CAPA_PORT_INUSE,
};
#define QTUTIL_CAPA(CAP) _IO(QTUTIL_IOCTL_CAPA_MAGIC, CAP)
#define QTUTIL_CAPA_PORT_INUSE		QTUTIL_CAPA(_QTUTIL_IOCTL_CAPA_PORT_INUSE)

// QTFS provide some remote syscalls
#define QTUTIL_IOCTL_SC_MAGIC 'S'
enum {
	_QTUTIL_IOCTL_SYSCALL_KILL,
	_QTUTIL_IOCTL_SYSCALL_SCHED_SETAFFINITY,
	_QTUTIL_IOCTL_SYSCALL_SCHED_GETAFFINITY,
};
#define QTUTIL_SYSCALL(SC) _IO(QTUTIL_IOCTL_SC_MAGIC, SC)
#define QTUTIL_SC_KILL					QTUTIL_SYSCALL(_QTUTIL_IOCTL_SYSCALL_KILL)
#define QTUTIL_SC_SCHED_SETAFFINITY		QTUTIL_SYSCALL(_QTUTIL_IOCTL_SYSCALL_SCHED_SETAFFINITY)
#define QTUTIL_SC_SCHED_GETAFFINITY		QTUTIL_SYSCALL(_QTUTIL_IOCTL_SYSCALL_SCHED_GETAFFINITY)

struct qtsc_kill {
	int pid;
	int signum;
};

// sched getaffinity and set affinity
struct qtsc_sched_affinity {
	int pid;
	unsigned int len;
	unsigned long *user_mask_ptr;
};


#endif

