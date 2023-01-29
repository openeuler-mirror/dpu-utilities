#ifndef __QTFS_UDS_MODULE_H__
#define __QTFS_UDS_MODULE_H__

#define UDS_BUILD_CONN_ADDR 	"/var/run/qtfs/remote_uds.sock"
#define UDS_DIAG_ADDR 		"/var/run/qtfs/uds_proxy_diag.sock"
#define UDS_LOGLEVEL_UPD 	"/var/run/qtfs/uds_loglevel.sock"
#define UDS_BUILD_CONN_DIR 	"/var/run/qtfs/"

#define UDS_SUN_PATH_LEN 108 // from glibc
struct uds_proxy_remote_conn_req {
	unsigned short type;
	unsigned short resv;
	char sun_path[UDS_SUN_PATH_LEN];
};
struct uds_proxy_remote_conn_rsp {
	int ret;
};

#endif
