package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type AlertSeverity int

const (
	SeverityInfo AlertSeverity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s AlertSeverity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

type DetectionRule string

const (
	RuleContainerEscape    DetectionRule = "container_escape"
	RuleCrossNSPtrace      DetectionRule = "cross_ns_ptrace"
	RuleCgroupReleaseAgent DetectionRule = "cgroup_release_agent_escape"
	RuleMountEscape        DetectionRule = "mount_escape"
	RulePrivilegedNS       DetectionRule = "privileged_namespace_creation"
	RuleShellInContainer   DetectionRule = "shell_in_container"
	RuleProcAccess         DetectionRule = "host_proc_access"
	RuleSuspiciousFork     DetectionRule = "suspicious_fork_bomb"
	RuleK8sExecInPod       DetectionRule = "k8s_exec_in_pod"
	RuleSensitiveMount     DetectionRule = "sensitive_mount"
)

type Alert struct {
	ID         string       `json:"id"`
	Timestamp  time.Time    `json:"timestamp"`
	Rule       DetectionRule `json:"rule"`
	Severity   AlertSeverity `json:"severity"`
	PID        uint32       `json:"pid"`
	Comm       string       `json:"comm"`
	Container  string       `json:"container_id,omitempty"`
	Namespace  string       `json:"namespace,omitempty"`
	Pod        string       `json:"pod,omitempty"`
	Message    string       `json:"message"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type ContainerInfo struct {
	ID        string    `json:"id"`
	PID       uint32    `json:"pid"`
	Comm      string    `json:"comm"`
	Namespace string    `json:"namespace,omitempty"`
	Pod       string    `json:"pod,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type ProcessNode struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Comm      string    `json:"comm"`
	Container string    `json:"container_id"`
	Children  []uint32  `json:"children"`
	Alerts    []string  `json:"alerts"`
	CreatedAt time.Time `json:"created_at"`
}

type Engine struct {
	mu           sync.RWMutex
	learningMode bool
	autoKill     bool
	containers   map[uint32]*ContainerInfo
	processTree  map[uint32]*ProcessNode
	alerts       []Alert
	baselines    map[string]*ContainerBaseline
	stats        Stats
}

type Stats struct {
	TotalProcesses      int            `json:"total_processes"`
	TotalContainers     int            `json:"total_containers"`
	TotalAlerts         int            `json:"total_alerts"`
	AlertsBySeverity    map[string]int `json:"alerts_by_severity"`
	AlertsByRule        map[string]int `json:"alerts_by_rule"`
	ContainersByPod     map[string]int `json:"containers_by_pod"`
	UptimeSeconds       int64          `json:"uptime_seconds"`
}

type ContainerBaseline struct {
	ContainerID string        `json:"container_id"`
	Processes   map[string]int `json:"processes"`
	Connections  map[string]int `json:"connections"`
	StartTime   time.Time     `json:"start_time"`
}

func NewEngine(learningMode, autoKill bool) *Engine {
	return &Engine{
		learningMode: learningMode,
		autoKill:     autoKill,
		containers:   make(map[uint32]*ContainerInfo),
		processTree:  make(map[uint32]*ProcessNode),
		alerts:       make([]Alert, 0),
		baselines:    make(map[string]*ContainerBaseline),
		stats: Stats{
			AlertsBySeverity: make(map[string]int),
			AlertsByRule:     make(map[string]int),
			ContainersByPod:  make(map[string]int),
			UptimeSeconds:    0,
		},
	}
}

func (e *Engine) RegisterContainer(pid uint32, comm string, containerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.containers[pid]; exists {
		return
	}

	e.containers[pid] = &ContainerInfo{
		ID:        containerID,
		PID:       pid,
		Comm:      comm,
		CreatedAt: time.Now(),
	}

	e.processTree[pid] = &ProcessNode{
		PID:       pid,
		Comm:      comm,
		Container: containerID,
		Children:  make([]uint32, 0),
		CreatedAt: time.Now(),
	}

	if e.learningMode {
		if _, exists := e.baselines[containerID]; !exists {
			e.baselines[containerID] = &ContainerBaseline{
				ContainerID: containerID,
				Processes:   make(map[string]int),
				Connections: make(map[string]int),
				StartTime:   time.Now(),
			}
		}
		e.baselines[containerID].Processes[comm]++
	}

	e.stats.TotalContainers = len(e.containers)
	e.stats.TotalProcesses = len(e.processTree)

	log.Printf("Container registered: %s (pid=%d, comm=%s)", containerID, pid, comm)
}

func (e *Engine) TrackProcessFork(parentPid, childPid uint32, parentComm, childComm string, containerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if parent, ok := e.processTree[parentPid]; ok {
		parent.Children = append(parent.Children, childPid)
	}

	e.processTree[childPid] = &ProcessNode{
		PID:       childPid,
		PPID:      parentPid,
		Comm:      childComm,
		Container: containerID,
		Children:  make([]uint32, 0),
		CreatedAt: time.Now(),
	}
	e.stats.TotalProcesses = len(e.processTree)

	if e.learningMode && containerID != "" {
		if bl, ok := e.baselines[containerID]; ok {
			bl.Processes[childComm]++
		}
	}
}

func (e *Engine) TrackProcessExit(pid uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.processTree, pid)
	e.stats.TotalProcesses = len(e.processTree)
}

func (e *Engine) RaiseAlert(rule DetectionRule, severity AlertSeverity, pid uint32, comm, containerID, message string, metadata map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()

	alert := Alert{
		ID:        fmt.Sprintf("%s-%d-%d", rule, pid, time.Now().UnixNano()),
		Timestamp: time.Now(),
		Rule:      rule,
		Severity:  severity,
		PID:       pid,
		Comm:      comm,
		Container: containerID,
		Message:   message,
		Metadata:  metadata,
	}

	e.alerts = append(e.alerts, alert)
	if len(e.alerts) > 10000 {
		e.alerts = e.alerts[len(e.alerts)-5000:]
	}

	e.stats.TotalAlerts++
	e.stats.AlertsBySeverity[severity.String()]++
	e.stats.AlertsByRule[string(rule)]++

	log.Printf("[%s] %s | pid=%d comm=%s container=%s | %s",
		severity.String(), rule, pid, comm, containerID, message)

	if e.nodeInContainer(pid, containerID) {
		if node, ok := e.processTree[pid]; ok {
			node.Alerts = append(node.Alerts, alert.ID)
		}
	}
}

func (e *Engine) nodeInContainer(pid uint32, containerID string) bool {
	node, ok := e.processTree[pid]
	if !ok {
		return false
	}
	return node.Container == containerID
}

func (e *Engine) GetAlerts() []Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]Alert, len(e.alerts))
	copy(result, e.alerts)
	return result
}

func (e *Engine) GetStats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := e.stats
	s.UptimeSeconds = int64(time.Since(time.Now().Add(-time.Duration(s.UptimeSeconds) * time.Second)).Seconds())
	if s.UptimeSeconds < 0 {
		s.UptimeSeconds = 0
	}
	return s
}

func (e *Engine) GetContainers() []*ContainerInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*ContainerInfo, 0, len(e.containers))
	for _, c := range e.containers {
		result = append(result, c)
	}
	return result
}

func (e *Engine) GetProcessTree() []*ProcessNode {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]*ProcessNode, 0, len(e.processTree))
	for _, n := range e.processTree {
		result = append(result, n)
	}
	return result
}

func (e *Engine) SetLearningMode(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.learningMode = enabled
	log.Printf("Learning mode: %v", enabled)
}
