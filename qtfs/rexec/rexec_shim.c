#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include "cJSON.h"

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

void rshim_reg_file_open(int fd_target, char *path, int perm, int offset)
{
    int fd = open(path, perm);
    int fd2 = -1;
    if (fd < 0) {
        rshim_err("Open file:%s failed, fd:%d err:%s", path, fd, strerror(errno));
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
    const cJSON *files;
    const cJSON *file;
    const cJSON *fd;
    const cJSON *path;
    const cJSON *perm;
    const cJSON *offset;
    int curfd = 3; // begin from 3
    cJSON *fd_json = cJSON_Parse(json_buf);
    if (fd_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
            fprintf(stderr, "Error before: %s\n", error_ptr);
        goto end;
    }
    files = cJSON_GetObjectItemCaseSensitive(fd_json, "Files");
    cJSON_ArrayForEach(file, files) {
        fd = cJSON_GetObjectItemCaseSensitive(file, "Fd");
        path = cJSON_GetObjectItemCaseSensitive(file, "Path");
        perm = cJSON_GetObjectItemCaseSensitive(file, "Perm");
        offset = cJSON_GetObjectItemCaseSensitive(file, "Offset");
        rshim_log("Get file from json fd:%d path:%s perm:%d offset:%d",
                fd->valueint, path->valuestring, perm->valueint, offset->valueint);
        rshim_reg_file_open(fd->valueint, path->valuestring, perm->valueint, offset->valueint);
    }

end:
    cJSON_Delete(fd_json);
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

    exit(EXIT_FAILURE);
}

