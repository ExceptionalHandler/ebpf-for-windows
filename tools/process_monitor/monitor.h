#pragma once
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_protocol.h"
#include "ebpf_api.h"

typedef struct _ebpf_ring_buffer_record
{
    // This struct should match the linux ring buffer record structure for future mmap compatibility (see #4163).
    struct
    {
        uint32_t length;      ///< High 2 bits are lock,discard.
        uint32_t page_offset; ///< Currently unused.
    } header;
    uint8_t data[1];
} ebpf_ring_buffer_record_t;



struct msg_common
{
    uint8_t op;
    uint8_t flags; // internal flags not exported
    uint8_t pad[2];
    uint32_t size;
    uint64_t ktime;
};



typedef enum _process_operation
{
    PROCESS_OPERATION_CREATE, ///< Process creation.
    PROCESS_OPERATION_DELETE, ///< Process deletion.
} process_operation_t;

typedef struct process_create_info_t
{
    struct msg_common common;
    uint32_t process_id;
    uint32_t parent_process_id;
    uint32_t creating_process_id;
    uint32_t creating_thread_id;
    uint64_t user_luid;
    uint64_t creation_time; ///< Process creation time.
} process_create_info ;

typedef struct process_exit_info_t
{
    struct msg_common common;
    uint32_t process_id;
    uint64_t exit_time; ///< Process exit time.
    uint32_t process_exit_code;
    uint8_t operation;
} process_exit_info;


struct msg_ip_tuple
{
    uint64_t saddr[2];
    uint64_t daddr[2];
    uint16_t dport;
    uint16_t sport;
    uint8_t proto;
    uint8_t send;
    uint8_t version_byte;
    uint8_t ipv6;
}; // All fields aligned so no 'packed' attribute.

struct msg_execve_key
{
    uint32_t pid; // Process TGID
    uint8_t pad[4];
    uint64_t ktime;
}; // All fields aligned so no 'packed' attribute.

struct msg_ip_event
{
    struct msg_common common;
    struct msg_ip_tuple tuple;
    unsigned long int ret;
    struct msg_execve_key key;
    uint64_t socket_cookie;
    uint32_t socket_flags;
    uint32_t pad;
    uint64_t version;
    uint64_t ps_version;  // pseudo-socket version (used in UDP).
    uint64_t create_time; // only used on close events.
    uint64_t close_time;  // only used on close events.
}; // All fields aligned so no 'packed' attribute.



int
loadProcess();
int
loadConnect();

int
unloadProcess();
int
unloadConnect();


int
process_creation_callback(_Inout_ void* ctx, _In_opt_ void* data, size_t size);


int
connection_callback(_Inout_ void* ctx, _In_opt_ void* data, size_t size);

void
preRecvProcess();
