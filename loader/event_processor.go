package main

import (
	"log"
	"time"
)

type BPFEventType uint32

const (
	EventFork           BPFEventType = 1
	EventExec           BPFEventType = 2
	EventExit           BPFEventType = 3
	EventConnect        BPFEventType = 4
	EventOpen           BPFEventType = 5
	EventPtrace         BPFEventType = 6
	EventMount          BPFEventType = 7
	EventCgroupWrite    BPFEventType = 8
	EventPidCrossNS     BPFEventType = 9
	EventPrivilegedNS   BPFEventType = 10
	EventContainerStart BPFEventType = 11
	EventShellSpawn     BPFEventType = 12
)

type RawBPFEvent struct {
	Type        BPFEventType
	PID         uint32
	PPID        uint32
	TID         uint32
	UID         uint32
	Ret         uint32
	TimestampNS uint64
	Comm        [16]byte
	ContainerID [64]byte
	Data        [296]byte
}

type ProcessMonitor struct {
	bpfLoader *BPFLoader
	engine    *Engine
}

func NewProcessMonitor(bpfLoader *BPFLoader, engine *Engine) *ProcessMonitor {
	return &ProcessMonitor{
		bpfLoader: bpfLoader,
		engine:    engine,
	}
}

func (pm *ProcessMonitor) Start() {
	log.Println("Process monitor started")

	reader, err := pm.bpfLoader.GetEventReader()
	if err != nil {
		log.Fatalf("Failed to get event reader: %v", err)
	}

	if reader == nil {
		log.Println("No eBPF reader available — running in mock/simulation mode")
		select {}
	}

	for {
		record, err := reader.Read()
		if err != nil {
			log.Printf("Error reading event: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if len(record.RawSample) < 16 {
			continue
		}

		pm.processRawEvent(record.RawSample)
	}
}

func (pm *ProcessMonitor) processRawEvent(data []byte) {
	if len(data) < 16 {
		return
	}

	eventType := BPFEventType(data[0])
	pid := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24

	containerID := extractContainerID(data)

	switch eventType {
	case EventFork:
		childPID := extractChildPID(data)
		comm := extractComm(data)
		parentComm := extractComm(data)
		pm.engine.TrackProcessFork(pid, childPID, parentComm, comm, containerID)
		log.Printf("FORK: parent=%d child=%d comm=%s container=%s", pid, childPID, comm, containerID)

	case EventExec:
		comm := extractComm(data)
		pm.engine.TrackProcessFork(0, pid, "", comm, containerID)
		log.Printf("EXEC: pid=%d comm=%s container=%s", pid, comm, containerID)

		if eventType == EventShellSpawn || pm.isSuspiciousExec(comm) {
			pm.engine.RaiseAlert(
				RuleShellInContainer,
				SeverityHigh,
				pid, comm, containerID,
				"Suspicious process executed in container: "+comm,
				map[string]any{"container_id": containerID},
			)
		}

	case EventExit:
		pm.engine.TrackProcessExit(pid)

	case EventPtrace, EventPidCrossNS:
		targetPID := extractTargetPID(data)
		comm := extractComm(data)
		pm.engine.RaiseAlert(
			RuleCrossNSPtrace,
			SeverityCritical,
			pid, comm, containerID,
			"Cross-namespace ptrace detected",
			map[string]any{"target_pid": targetPID, "container_id": containerID},
		)

	case EventMount:
		mountTarget := extractMountTarget(data)
		comm := extractComm(data)
		if isSensitiveMount(mountTarget) {
			pm.engine.RaiseAlert(
				RuleSensitiveMount,
				SeverityHigh,
				pid, comm, containerID,
				"Sensitive mount detected: "+mountTarget,
				map[string]any{"mount_target": mountTarget},
			)
		} else if containerID != "" {
			pm.engine.RaiseAlert(
				RuleMountEscape,
				SeverityHigh,
				pid, comm, containerID,
				"Mount syscall from container: "+mountTarget,
				map[string]any{"mount_target": mountTarget},
			)
		}

	case EventCgroupWrite:
		comm := extractComm(data)
		pm.engine.RaiseAlert(
			RuleCgroupReleaseAgent,
			SeverityCritical,
			pid, comm, containerID,
			"Cgroup release_agent write attempt (container escape)",
			map[string]any{},
		)

	case EventPrivilegedNS:
		comm := extractComm(data)
		pm.engine.RaiseAlert(
			RulePrivilegedNS,
			SeverityCritical,
			pid, comm, containerID,
			"Privileged namespace creation (possible escape)",
			map[string]any{},
		)

	case EventContainerStart:
		containerID := extractContainerID(data)
		comm := extractComm(data)
		pm.engine.RegisterContainer(pid, comm, containerID)
	}
}

func (pm *ProcessMonitor) isSuspiciousExec(comm string) bool {
	suspicious := []string{
		"bash", "sh", "zsh", "dash", "ksh",
		"nc", "ncat", "netcat",
		"nmap", "masscan",
		"curl", "wget",
		"perl", "python", "python3", "ruby", "lua",
		"gcc", "clang", "make",
		"msfvenom", "meterpreter",
		"socat", "proxychains",
		"kubectl", "helm",
	}
	for _, s := range suspicious {
		if comm == s {
			return true
		}
	}
	return false
}

func isSensitiveMount(target string) bool {
	sensitive := []string{
		"/etc", "/var/log", "/var/run", "/var/lib/kubelet",
		"/sys/kernel", "/proc", "/dev",
		"/host", "/root",
		"/var/run/docker.sock", "/run/docker.sock",
		"/var/lib/docker", "/var/lib/containerd",
	}
	for _, s := range sensitive {
		if len(target) >= len(s) && target[:len(s)] == s {
			return true
		}
	}
	return false
}

func extractContainerID(data []byte) string {
	if len(data) < 80 {
		return ""
	}
	id := string(data[16:80])
	for i, c := range id {
		if c == 0 {
			return id[:i]
		}
	}
	return id
}

func extractChildPID(data []byte) uint32 {
	if len(data) < 112 {
		return 0
	}
	return uint32(data[108]) | uint32(data[109])<<8 |
		uint32(data[110])<<16 | uint32(data[111])<<24
}

func extractComm(data []byte) string {
	if len(data) < 16 {
		return ""
	}
	comm := string(data[8:24])
	for i, c := range comm {
		if c == 0 {
			return comm[:i]
		}
	}
	return comm
}

func extractTargetPID(data []byte) uint32 {
	if len(data) < 112 {
		return 0
	}
	return uint32(data[108]) | uint32(data[109])<<8 |
		uint32(data[110])<<16 | uint32(data[111])<<24
}

func extractMountTarget(data []byte) string {
	if len(data) < 200 {
		return ""
	}
	target := string(data[112:200])
	for i, c := range target {
		if c == 0 {
			return target[:i]
		}
	}
	return target
}
