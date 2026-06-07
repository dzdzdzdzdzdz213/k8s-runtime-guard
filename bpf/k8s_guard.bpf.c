#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline __u32 get_pid_ns(void) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct pid *pid_struct;
  struct upid *upid;
  int level;
  __u32 ns;

  pid_struct = BPF_CORE_READ(task, thread_pid);
  level = BPF_CORE_READ(pid_struct, level);
  upid = &BPF_CORE_READ(pid_struct, numbers[level]);

  ns = BPF_CORE_READ(upid, ns, ns, inum);
  return ns;
}

static __always_inline int get_container_id(char *buf, int size) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct css_set *cgroups;
  struct cgroup_subsys_state *css;
  struct cgroup *cg;
  char *path;
  int ret;

  cgroups = BPF_CORE_READ(task, cgroups);
  if (!cgroups) return -1;

  css = BPF_CORE_READ(cgroups, subsys[0]);
  if (!css) return -1;

  cg = BPF_CORE_READ(css, cgroup);
  if (!cg) return -1;

  path = BPF_CORE_READ(cg, kn, name, name);
  if (!path) return -1;

  ret = bpf_probe_read_str(buf, size, path);
  if (ret > 0 && ret < CONTAINER_ID_LEN - 1) return 0;

  return -1;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
  struct event ev = {};
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u32 child_pid = ctx->child_pid;

  ev.type = EVENT_FORK;
  ev.pid = pid;
  ev.tid = (__u32)bpf_get_current_pid_tgid();
  ev.timestamp_ns = bpf_ktime_get_ns();
  ev.data.fork.child_pid = child_pid;
  bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

  struct container_info *cinfo = bpf_map_lookup_elem(&container_map, &pid);
  if (cinfo) {
    __builtin_memcpy(ev.container_id, cinfo->id, CONTAINER_ID_LEN);
    bpf_map_update_elem(&container_map, &child_pid, cinfo, BPF_ANY);
    __u32 ns = cinfo->pid_ns;
    bpf_map_update_elem(&pid_ns_map, &child_pid, &ns, BPF_ANY);
    __u32 ppid = pid;
    bpf_map_update_elem(&container_ppid_map, &child_pid, &ppid, BPF_ANY);
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
  struct event ev = {};
  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  ev.type = EVENT_EXEC;
  ev.pid = pid;
  ev.tid = (__u32)bpf_get_current_pid_tgid();
  ev.timestamp_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

  struct container_info *cinfo = bpf_map_lookup_elem(&container_map, &pid);
  if (cinfo) {
    __builtin_memcpy(ev.container_id, cinfo->id, CONTAINER_ID_LEN);

    __u32 *ppid = bpf_map_lookup_elem(&container_ppid_map, &pid);
    if (ppid) {
      __builtin_memcpy(&ev.data.shell_spawn.parent_pid, ppid, sizeof(__u32));
      struct container_info *pinfo = bpf_map_lookup_elem(&container_map, ppid);
      if (pinfo) {
        __builtin_memcpy(ev.data.shell_spawn.parent_comm, pinfo->comm, TASK_COMM_LEN);
      }
    }

    if (ev.comm[0] == 's' && ev.comm[1] == 'h') {
      ev.type = EVENT_SHELL_SPAWN;
    }
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
  struct event ev = {};
  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  ev.type = EVENT_EXIT;
  ev.pid = pid;
  ev.timestamp_ns = bpf_ktime_get_ns();
  ev.data.exit.exit_code = ctx->exit_code;

  struct container_info *cinfo = bpf_map_lookup_elem(&container_map, &pid);
  if (cinfo) {
    __builtin_memcpy(ev.container_id, cinfo->id, CONTAINER_ID_LEN);
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

  bpf_map_delete_elem(&container_map, &pid);
  bpf_map_delete_elem(&pid_ns_map, &pid);
  bpf_map_delete_elem(&container_ppid_map, &pid);

  return 0;
}

SEC("kprobe/security_ptrace_access_check")
int kprobe_ptrace_access(struct pt_regs *ctx) {
  struct event ev = {};
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u32 current_ns = get_pid_ns();

  struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(ctx);
  __u32 target_pid = BPF_CORE_READ(task, pid);
  __u32 target_ns;
  struct pid *target_pid_struct = BPF_CORE_READ(task, thread_pid);
  struct upid *target_upid;
  int level = BPF_CORE_READ(target_pid_struct, level);

  target_upid = &BPF_CORE_READ(target_pid_struct, numbers[level]);
  target_ns = BPF_CORE_READ(target_upid, ns, ns, inum);

  if (current_ns != target_ns) {
    ev.type = EVENT_PTRACE;
    ev.pid = pid;
    ev.uid = (__u32)bpf_get_current_uid_gid();
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.data.ptrace.target_pid = target_pid;
    ev.data.ptrace.addr_type = 1;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    struct container_info *cinfo = bpf_map_lookup_elem(&container_map, &pid);
    if (cinfo) {
      __builtin_memcpy(ev.container_id, cinfo->id, CONTAINER_ID_LEN);
      ev.type = EVENT_PID_CROSS_NS;
      ev.data.ns_cross.target_ns = target_ns;
      ev.data.ns_cross.current_ns = current_ns;
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  }

  return 0;
}

SEC("kprobe/do_mount")
int kprobe_do_mount(struct pt_regs *ctx) {
  struct event ev = {};
  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  ev.type = EVENT_MOUNT;
  ev.pid = pid;
  ev.timestamp_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

  const char *source = (const char *)PT_REGS_PARM1(ctx);
  const char *target = (const char *)PT_REGS_PARM2(ctx);
  const char *fstype = (const char *)PT_REGS_PARM3(ctx);

  bpf_probe_read_str(&ev.data.mount.target, sizeof(ev.data.mount.target), target);
  bpf_probe_read_str(&ev.data.mount.fstype, sizeof(ev.data.mount.fstype), fstype);

  struct container_info *cinfo = bpf_map_lookup_elem(&container_map, &pid);
  if (cinfo) {
    __builtin_memcpy(ev.container_id, cinfo->id, CONTAINER_ID_LEN);
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  return 0;
}

SEC("kprobe/cgroup_attach_task")
int kprobe_cgroup_attach(struct pt_regs *ctx) {
  struct event ev = {};
  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  ev.type = EVENT_CGROUP_WRITE;
  ev.pid = pid;
  ev.timestamp_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

  struct container_info *cinfo = bpf_map_lookup_elem(&container_map, &pid);
  if (cinfo) {
    __builtin_memcpy(ev.container_id, cinfo->id, CONTAINER_ID_LEN);
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_sys_enter_clone(struct trace_event_raw_sys_enter *ctx) {
  struct event ev = {};
  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  unsigned long flags = (unsigned long)ctx->args[0];
  __u32 current_ns = get_pid_ns();

  ev.type = EVENT_CONTAINER_START;
  ev.pid = pid;
  ev.timestamp_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

  int is_new_ns = 0;
  struct container_info *cinfo = bpf_map_lookup_elem(&container_map, &pid);

  if (flags & CLONE_NEWNS) {
    is_new_ns = 1;
    ev.data.ns_cross.current_ns = current_ns;
    ev.type = EVENT_PRIVILEGED_NS;
  }
  if (flags & CLONE_NEWPID) {
    is_new_ns = 1;
    ev.type = EVENT_PRIVILEGED_NS;
  }
  if (flags & CLONE_NEWNET) {
    is_new_ns = 1;
    ev.type = EVENT_PRIVILEGED_NS;
  }

  if (cinfo && is_new_ns && (flags & (CLONE_NEWNS | CLONE_NEWPID))) {
    ev.type = EVENT_PRIVILEGED_NS;
    __builtin_memcpy(ev.container_id, cinfo->id, CONTAINER_ID_LEN);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  }

  return 0;
}

SEC("kprobe/proc_reg")
int kprobe_proc_reg(struct pt_regs *ctx) {
  struct event ev = {};
  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct container_info *cinfo = bpf_map_lookup_elem(&container_map, &pid);
  if (!cinfo) return 0;

  const char *filename = (const char *)PT_REGS_PARM1(ctx);
  char buf[32] = {};

  bpf_probe_read_str(buf, sizeof(buf), filename);

  #pragma unroll
  for (int i = 0; i < 24; i++) {
    if (buf[i] == '/' && buf[i+1] == 'p' && buf[i+2] == 'r' && buf[i+3] == 'o' && buf[i+4] == 'c') {
      __builtin_memcpy(ev.container_id, cinfo->id, CONTAINER_ID_LEN);
      ev.type = EVENT_OPEN;
      ev.pid = pid;
      ev.timestamp_ns = bpf_ktime_get_ns();
      bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
      bpf_probe_read_str(&ev.data.open.filename, sizeof(ev.data.open.filename), filename);
      ev.data.open.flags = 0;
      bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
      break;
    }
  }

  return 0;
}

SEC("kprobe/cgroup_release_agent")
int kprobe_cgroup_release_agent(struct pt_regs *ctx) {
  struct event ev = {};
  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct container_info *cinfo = bpf_map_lookup_elem(&container_map, &pid);
  if (!cinfo) return 0;

  const char *filename = (const char *)PT_REGS_PARM1(ctx);
  char buf[64] = {};
  bpf_probe_read_str(buf, sizeof(buf), filename);

  for (int i = 0; i < 60; i++) {
    if (buf[i] == 'r' && buf[i+1] == 'e' && buf[i+2] == 'l' && buf[i+3] == 'e' && buf[i+4] == 'a' && buf[i+5] == 's' && buf[i+6] == 'e' && buf[i+7] == '_' && buf[i+8] == 'a' && buf[i+9] == 'g' && buf[i+10] == 'e' && buf[i+11] == 'n' && buf[i+12] == 't') {
      __builtin_memcpy(ev.container_id, cinfo->id, CONTAINER_ID_LEN);
      ev.type = EVENT_CGROUP_WRITE;
      ev.pid = pid;
      ev.timestamp_ns = bpf_ktime_get_ns();
      bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
      bpf_probe_read_str(&ev.data.cgroup_write.cgroup_path, sizeof(ev.data.cgroup_write.cgroup_path), buf);
      ev.data.cgroup_write.data[0] = 'r';
      ev.data.cgroup_write.data[1] = 'e';
      ev.data.cgroup_write.data[2] = 'l';
      ev.data.cgroup_write.data[3] = 'e';
      ev.data.cgroup_write.data[4] = 'a';
      ev.data.cgroup_write.data[5] = 's';
      ev.data.cgroup_write.data[6] = 'e';
      ev.data.cgroup_write.data[7] = '_';
      ev.data.cgroup_write.data[8] = 'a';
      ev.data.cgroup_write.data[9] = 'g';
      ev.data.cgroup_write.data[10] = 'e';
      ev.data.cgroup_write.data[11] = 'n';
      ev.data.cgroup_write.data[12] = 't';
      bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
      break;
    }
  }

  return 0;
}
