#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define PATH_MAX 256
#define CONTAINER_ID_LEN 64

#ifndef __uint
#define __uint(name, sz) \
  int(*name)[sz]
#endif

enum event_type {
  EVENT_FORK = 1,
  EVENT_EXEC = 2,
  EVENT_EXIT = 3,
  EVENT_CONNECT = 4,
  EVENT_OPEN = 5,
  EVENT_PTRACE = 6,
  EVENT_MOUNT = 7,
  EVENT_CGROUP_WRITE = 8,
  EVENT_PID_CROSS_NS = 9,
  EVENT_PRIVILEGED_NS = 10,
  EVENT_CONTAINER_START = 11,
  EVENT_SHELL_SPAWN = 12,
};

struct container_info {
  char id[CONTAINER_ID_LEN];
  __u32 pid_ns;
  __u32 mnt_ns;
  __u32 net_ns;
  __u32 pid;
};

struct event {
  enum event_type type;
  __u32 pid;
  __u32 ppid;
  __u32 tid;
  __u32 uid;
  __u32 gid;
  __u32 ret;
  __u64 timestamp_ns;
  char comm[TASK_COMM_LEN];
  char container_id[CONTAINER_ID_LEN];
  union {
    struct {
      char filename[PATH_MAX];
      __u32 flags;
    } open;
    struct {
      __u32 saddr;
      __u32 daddr;
      __u16 dport;
      __u16 sport;
      __u32 pid_ns;
    } connect;
    struct {
      __u32 target_pid;
      __u32 addr_type;
    } ptrace;
    struct {
      __u64 mount_ns;
      __u64 mnt_id;
      char target[PATH_MAX];
      char fstype[16];
    } mount;
    struct {
      __u32 child_pid;
      char child_comm[TASK_COMM_LEN];
    } fork;
    struct {
      __u64 exit_code;
    } exit;
    struct {
      char cgroup_path[PATH_MAX];
      char data[256];
    } cgroup_write;
    struct {
      __u32 target_ns;
      __u32 current_ns;
    } ns_cross;
    struct {
      __u32 parent_pid;
      char parent_comm[TASK_COMM_LEN];
    } shell_spawn;
  } data;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 4096);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, struct container_info);
} container_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, __u32);
} pid_ns_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, __u32);
} container_ppid_map SEC(".maps");

#endif
