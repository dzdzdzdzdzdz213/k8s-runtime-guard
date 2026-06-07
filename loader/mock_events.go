//go:build !linux

package main

import (
	"log"
	"time"
)

type BPFLoader struct {
	engine *Engine
}

func NewBPFLoader(eng *Engine) (*BPFLoader, error) {
	log.Println("eBPF not available on this platform — running in simulation mode")
	log.Println("Container escape events will be simulated for testing")
	ld := &BPFLoader{engine: eng}
	ld.startMockEvents()
	return ld, nil
}

func (ld *BPFLoader) GetEventReader() (interface{}, error) {
	return nil, nil
}

func (ld *BPFLoader) Close() {
	log.Println("Simulation loader closed")
}

func (ld *BPFLoader) startMockEvents() {
	log.Println("Starting mock event generator...")

	go func() {
		time.Sleep(500 * time.Millisecond)

		ld.engine.RegisterContainer(1001, "containerd-shim", "a1b2c3d4e5")
		ld.engine.RegisterContainer(1002, "kubelet", "f6g7h8i9j0")

		time.Sleep(2 * time.Second)

		ld.engine.RaiseAlert(
			RuleCrossNSPtrace,
			SeverityCritical,
			1001, "bash", "a1b2c3d4e5",
			"Cross-namespace ptrace: process in container attempted to ptrace host process",
			map[string]any{"target_pid": 1, "target_comm": "systemd"},
		)

		time.Sleep(1 * time.Second)

		ld.engine.RaiseAlert(
			RuleCgroupReleaseAgent,
			SeverityCritical,
			1002, "sh", "f6g7h8i9j0",
			"Cgroup release_agent write — container escape technique (CVE-2022-0492)",
			map[string]any{"technique": "release_agent", "cve": "CVE-2022-0492"},
		)

		time.Sleep(1 * time.Second)

		ld.engine.RaiseAlert(
			RuleMountEscape,
			SeverityHigh,
			1001, "bash", "a1b2c3d4e5",
			"Mount syscall from container — possible host filesystem access",
			map[string]any{"target": "/host/etc"},
		)

		time.Sleep(1 * time.Second)

		ld.engine.RaiseAlert(
			RuleShellInContainer,
			SeverityHigh,
			1003, "sh", "a1b2c3d4e5",
			"Interactive shell spawned in container — possible exec into pod",
			map[string]any{"parent_comm": "nginx"},
		)

		for i := 0; i < 30; i++ {
			pid := uint32(2000 + i)
			ld.engine.TrackProcessFork(1001, pid, "bash", "sleep", "a1b2c3d4e5")
			time.Sleep(100 * time.Millisecond)
		}

		ld.engine.RaiseAlert(
			RuleSuspiciousFork,
			SeverityMedium,
			1001, "bash", "a1b2c3d4e5",
			"Rapid process fork detected — possible fork bomb or resource exhaustion",
			map[string]any{"fork_count": 30, "time_window_sec": 3},
		)

		log.Println("Mock events complete — API server is ready")
	}()
}
