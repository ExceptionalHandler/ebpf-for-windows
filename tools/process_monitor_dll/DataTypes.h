#pragma once
#include <stdint.h>

typedef enum _process_operation
{
    PROCESS_OPERATION_CREATE, ///< Process creation.
    PROCESS_OPERATION_DELETE, ///< Process deletion.
} process_operation_t;

typedef struct
{
    uint32_t process_id;
    uint32_t parent_process_id;
    uint32_t creating_process_id;
    uint32_t creating_thread_id;
    uint64_t creation_time; ///< Process creation time.
    uint64_t exit_time;     ///< Process exit time.
    uint32_t process_exit_code;
    uint8_t operation;
} process_info_t;



struct msg_process
{
    uint32_t size;
    uint32_t pid; // Process TGID
    uint32_t tid; // Process thread
    uint32_t nspid;
    uint32_t secureexec;
    uint32_t uid;
    uint32_t auid;
    uint32_t flags;
    uint32_t i_nlink;
    uint32_t pad;
    uint64_t i_ino;
    uint64_t ktime;
    char args[MAX_PATH];
}; // All fields aligned so no 'packed' attribute.


struct msg_k8s
{
    uint64_t cgrpid;
    uint64_t cgrp_tracker_id;
    char docker_id[128];
}; // All fields aligned so no 'packed' attribute.

struct msg_execve_key
{
    uint32_t pid; // Process TGID
    uint8_t pad[4];
    uint64_t ktime;
};

struct msg_capabilities
{
    union
    {
        struct
        {
            uint64_t permitted;
            uint64_t effective;
            uint64_t inheritable;
        };
        uint64_t c[3];
    };
}; // All fields aligned so no 'packed' attribute.


struct msg_user_namespace
{
    int level;
    uint32_t uid;
    uint32_t gid;
    uint32_t ns_inum;
};



struct msg_cred
{
    uint32_t uid;
    uint32_t gid;
    uint32_t suid;
    uint32_t sgid;
    uint32_t euid;
    uint32_t egid;
    uint32_t fsuid;
    uint32_t fsgid;
    uint32_t securebits;
    uint32_t pad;
    struct msg_capabilities caps;
    struct msg_user_namespace user_ns;
};


struct msg_ns
{
    union
    {
        struct
        {
            uint32_t uts_inum;
            uint32_t ipc_inum;
            uint32_t mnt_inum;
            uint32_t pid_inum;
            uint32_t pid_for_children_inum;
            uint32_t net_inum;
            uint32_t time_inum;
            uint32_t time_for_children_inum;
            uint32_t cgroup_inum;
            uint32_t user_inum;
        };
        uint32_t inum[10];
    };
};


/* Msg Layout */
struct msg_common
{
    uint8_t op;
    uint8_t flags; // internal flags not exported
    uint8_t pad[2];
    uint32_t size;
    uint64_t ktime;
};

typedef struct __msg_execve_event
{
    struct msg_common common;
    struct msg_k8s kube;
    struct msg_execve_key parent;
    uint64_t parent_flags;
    struct msg_cred creds;
    struct msg_ns ns;
    struct msg_execve_key cleanup_key;
    /* if add anything above please also update the args of
     * validate_msg_execve_size() in bpf_execve_event.c */
    union
    {
        struct msg_process process;
        char buffer[1024 + 256 + 56 + 56 + 256];
    };
} msg_execve_event, * ptr_msg_execve_event; // All fields aligned so no 'packed' attribute.


int
EnqueEvent(process_info_t* process_info, wchar_t* path); 
