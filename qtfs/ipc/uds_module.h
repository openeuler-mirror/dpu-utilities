/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * qtfs licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Liqiang
 * Create: 2023-03-20
 * Description: 
 *******************************************************************************/

#ifndef __QTFS_UDS_MODULE_H__
#define __QTFS_UDS_MODULE_H__

#define UDS_BUILD_CONN_ADDR 	"/var/run/qtfs/remote_uds.sock"
#define UDS_DIAG_ADDR 		"/var/run/qtfs/uds_proxy_diag.sock"
#define UDS_LOGLEVEL_UPD 	"/var/run/qtfs/uds_loglevel.sock"
#define UDS_LOCK_ADDR		"/var/run/qtfs/uds.lock"
#define UDS_BUILD_CONN_DIR 	"/var/run/qtfs/"

#define UDS_PROXY_SUFFIX ".proxy"

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
