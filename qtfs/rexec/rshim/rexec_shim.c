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

#define RSHIM_LOG_FILE "/var/run/rexec/rexec_shim.log"
#define rshim_log(info, ...) \
    do { \
        time_t t; \
        struct tm *p; \
        time(&t); \
        p = localtime(&t); \
        printf("[%d/%02d/%02d %02d:%02d:%02d][LOG:%s:%3d]"info"\n", \
                p->tm_year + 1900, p->tm_mon+1, p->tm_mday, \
        p->tm_hour, p->tm_min, p->tm_sec, __func__, __LINE__, ##__VA_ARGS__); \
    } while (0);

#define rshim_err(info, ...) \
    do { \
        time_t t; \
        struct tm *p; \
        time(&t); \
        p = localtime(&t); \
        printf("[%d/%02d/%02d %02d:%02d:%02d][LOG:%s:%3d]"info"\n", \
                p->tm_year + 1900, p->tm_mon+1, p->tm_mday, \
        p->tm_hour, p->tm_min, p->tm_sec, __func__, __LINE__, ##__VA_ARGS__); \
    } while (0);

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

void rshim_reg_file_sync(char *json_file)
{
#define RSHIM_JSON_SIZE_MAX 1024*1024*1024 // 限制为1M足够了
    rshim_close_all_fd();
    if (json_file == NULL)
        return;

    int json_size = rshim_get_file_size(json_file);
    if (json_size < 0 || json_size > RSHIM_JSON_SIZE_MAX) {
        rshim_err("Get json file:%s size failed, size:%d.", json_file, json_size);
        return;
    }
    rshim_log("Get json file:%s size:%d", json_file, json_size);

    char *json_buf = (char *)malloc(json_size + 1);
    int json_len = 0;
    if (json_buf == NULL) {
        rshim_err("Malloc error.");
        return;
    }
    memset(json_buf, 0, json_size + 1);
    int json_fd = open(json_file, O_RDONLY);
    if (json_fd < 0) {
        rshim_err("Open json file:%s failed, err:%s", json_file, strerror(errno));
        goto end;
    }
    json_len = read(json_fd, json_buf, json_size + 1);
    if (json_len <= 0) {
        rshim_err("Failed to read from json file:%s, ret:%d err:%s", json_file, json_len, strerror(errno));
        close(json_fd);
        goto end;
    }
    close(json_fd);
    remove(json_file);
    rshim_reg_file_resume((const char * const)json_buf);
end:
    free(json_buf);
    return;
}

/*  
    param list:
       1) -f xxx.json binary param1 param2 ...
       2) binary param1 param2...
*/
int main(int argc, char *argv[])
{
    char *json_file = NULL;
    char **newarg = NULL;

    // 至少得有需要执行的二进制名称
    if (argc < 2 || (strcmp(argv[1], "-f") == 0 && argc < 4)) {
        rshim_err("Input argument list too short.");
        return -1;
    }

    if (strcmp(argv[1], "-f") == 0) {
        json_file = argv[2];
        newarg = &argv[3];
    } else {
        newarg = &argv[1];
    }

    rshim_reg_file_sync(json_file);
    execvp(newarg[0], newarg);
    perror("execve failed.");

    exit(EXIT_FAILURE);
}

