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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>

#include "dirent.h"
#include "rexec.h"

#define rshim_log rexec_log
#define rshim_err rexec_err

void rshim_close_all_fd()
{
	DIR *dir = NULL;
	struct dirent *entry;
	dir = opendir("/proc/self/fd/");
	if (dir == NULL) {
		rshim_err("open path:/proc/self/fd/ failed");
		return;
	}
	while (entry = readdir(dir)) {
		int fd = atoi(entry->d_name);
		if (fd <= 2)
			continue;
		close(fd);
	}
	closedir(dir);
	return;
}

int rshim_get_file_size(char *file)
{
	int size = 0;
	FILE *f = fopen(file, "rb");
	if (f == NULL) {
		rshim_err("File:%s fopen failed.", file);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fclose(f);
	return size;
}

void rshim_reg_file_open(int fd_target, const char *path, int perm, int offset)
{
	int fd = open(path, perm);
	int fd2 = -1;
	if (fd < 0) {
		rshim_err("Open file:%s failed, fd:%d errno:%d", path, fd, errno);
		return;
	}
	if (fd != fd_target) {
		fd2 = dup2(fd, fd_target);
		if (fd2 != fd_target) {
			rshim_err("Failed to open file:%s by fd:%d", path, fd_target);
			close(fd2);
			close(fd);
			return;
		}
		close(fd);
	}
	int off = lseek(fd_target, offset, SEEK_SET);
	if (off < 0) {
		rshim_err("Failed to set offset:%d to file:%s, fd:%d, fd2:%d", offset, path, fd, fd2);
		return;
	}
	rshim_log("Successed to set offset:%d to file:%s, fd:%d, fd2:%d", offset, path, fd, fd2);
	return;
}

void rshim_reg_file_resume(const char * const json_buf)
{
	struct json_object *obj_files;
	struct json_object *obj_file;
	struct json_object *obj_fd;
	struct json_object *obj_path;
	struct json_object *obj_perm;
	struct json_object *obj_offset;
	int fd, perm, offset;
	const char *path = NULL;
	int curfd = 3; // begin from 3
	struct json_object *fd_json = json_tokener_parse(json_buf);
	if (fd_json == NULL) {
		fprintf(stderr, "parse json error\n");
		return;
	}
	obj_files = json_object_object_get(fd_json, "Files");
	int arraylen = json_object_array_length(obj_files);
	for (int i=0; i< arraylen; i++){
		obj_file = json_object_array_get_idx(obj_files, i);
		obj_fd = json_object_object_get(obj_file, "Fd");
		fd = json_object_get_int(obj_fd);
		obj_path = json_object_object_get(obj_file, "Path");
		path = json_object_get_string(obj_path);
		obj_perm = json_object_object_get(obj_file, "Perm");
		perm = json_object_get_int(obj_perm);
		obj_offset = json_object_object_get(obj_file, "Offset");
		offset = json_object_get_int(obj_offset);
		rshim_log("Get file from json fd:%d path:%s perm:%d offset:%d",
				fd, path, perm, offset);
		rshim_reg_file_open(fd, path, perm, offset);
	}

	json_object_put(fd_json);
	return;
}

/*  
	param list:
	   1) -f xxx.json binary param1 param2 ...
	   2) binary param1 param2...
*/
int rexec_shim_entry(int argc, char *argv[])
{
	char *json_str = NULL;
	char **newarg = NULL;

	if (strcmp(argv[0], "-f") == 0) {
		json_str = argv[1];
		newarg = &argv[2];
	} else {
		newarg = argv;
	}

	rshim_close_all_fd();

	rshim_log("Get json str:%s", json_str);

	rshim_reg_file_resume(json_str);
	execvp(newarg[0], newarg);
	perror("execvp failed.");

	return -1;
}

