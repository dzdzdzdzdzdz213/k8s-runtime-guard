# K8s Runtime Guard

Container-aware runtime security powered by eBPF. Detects container escape attempts, cross-namespace attacks, and suspicious container behavior by hooking kernel syscalls and correlating with Kubernetes audit logs.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    K8s Runtime Guard                  │
│                                                       │
│  ┌──────────────┐    ┌──────────────┐                 │
│  │  eBPF Hooks   │───▶│  Ring Buffer  │                 │
│  │  (kernel)     │    │  (kernel)    │                 │
│  └──────────────┘    └──────┬───────┘                 │
│                             │                         │
│  ┌──────────────────────────▼──────────────────────┐ │
│  │           Event Processor (Go)                   │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │ │
│  │  │ Container │  │ Process  │  │ K8s Audit   │   │ │
│  │  │ Tracking  │  │ Lineage  │  │ Correlation  │   │ │
│  │  └──────────┘  └──────────┘  └──────────────┘   │ │
│  └──────────────────────┬───────────────────────────┘ │
│                         │                             │
│  ┌──────────────────────▼──────────────────────────┐ │
│  │         Detection Engine                         │ │
│  │  ┌──────────────────────────────────────────┐    │ │
│  │  │  Container Escape    │  Cross-NS Attacks  │    │ │
│  │  │  Privileged NS       │  Cgroup Escapes    │    │ │
│  │  │  Mount Escapes       │  Shell in Pod      │    │ │
│  │  │  Host /proc Access   │  Fork Bombs        │    │ │
│  │  └──────────────────────────────────────────┘    │ │
│  └──────────────────────┬───────────────────────────┘ │
│                         │                             │
│  ┌──────────────────────▼──────────────────────────┐ │
│  │          REST API + SSE (port 9090)              │ │
│  └──────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `container_escape` | Critical | Generic container escape pattern |
| `cross_ns_ptrace` | Critical | Ptrace across namespace boundary |
| `cgroup_release_agent_escape` | Critical | Cgroup release_agent write (CVE-2022-0492) |
| `mount_escape` | High | Mount syscall from within container |
| `privileged_namespace_creation` | Critical | Container creating new namespaces (CLONE_NEWNS/NEWPID/NEWNET) |
| `shell_in_container` | High | Interactive shell (sh/bash/zsh) or suspicious binary spawned in container |
| `host_proc_access` | High | Container process accessing /proc filesystem |
| `suspicious_fork_bomb` | Medium | Rapid process forking within container |
| `k8s_exec_in_pod` | High | kubectl exec detected via K8s audit log |
| `sensitive_mount` | High | Container mounting sensitive host paths |

## eBPF Hooks

- `sched_process_fork` — track process creation lineage per container
- `sched_process_exec` — detect shell spawns and suspicious binaries
- `sched_process_exit` — clean up process tracking state
- `sys_enter_clone` — detect namespace creation flags
- `security_ptrace_access_check` — cross-namespace ptrace detection
- `do_mount` — detect mount syscalls from containers
- `cgroup_attach_task` — detect cgroup manipulation
- `proc_reg` — detect /proc filesystem access from containers
- `cgroup_release_agent` — detect release_agent escape technique

## Quick Start

### Prerequisites

- Linux kernel 5.4+ with BPF support (for eBPF mode)
- Go 1.22+
- Docker (for K8s integration)

### Run with mock events (Windows/dev)

```bash
cd loader
go run .
```

This runs in simulation mode — generates realistic container escape scenarios for testing the detection engine and API.

### Run with eBPF (Linux)

```bash
cd loader
go generate
go build -o k8s-runtime-guard .
sudo ./k8s-runtime-guard
```

### Configuration

Edit `config.json`:

```json
{
  "learning_mode": true,
  "auto_kill": false,
  "api_port": 9090,
  "kubeconfig": "/path/to/kubeconfig"
}
```

Toggle at runtime:

```bash
curl -X POST http://localhost:9090/api/v1/config \
  -H 'Content-Type: application/json' \
  -d '{"learning_mode": false}'
```

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/stats` | GET | Runtime statistics |
| `/api/v1/alerts` | GET | Alert history |
| `/api/v1/containers` | GET | Registered containers |
| `/api/v1/processes` | GET | Process tree |
| `/api/v1/config` | GET/POST | Runtime configuration |
| `/api/v1/events` | GET | SSE streaming events |

## Tech Stack

- **Kernel**: C (eBPF) — 9 kernel probes and tracepoints
- **Userspace**: Go — cilium/ebpf, ring buffer, REST API
- **Detection**: Behavioral engine with per-process baselines and learning mode
- **Integration**: K8s audit log parsing for exec/attach correlation
- **Deployment**: Docker, privileged container (for eBPF access)
