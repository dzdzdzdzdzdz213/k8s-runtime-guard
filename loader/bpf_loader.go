//go:build linux

package main

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type BPFLoader struct {
	objs  bpfObjects
	links []link.Link
	engine *Engine
}

func NewBPFLoader(eng *Engine) (*BPFLoader, error) {
	ld := &BPFLoader{engine: eng}

	if err := loadBpfObjects(&ld.objs, nil); err != nil {
		return nil, err
	}

	tracepoints := []struct {
		name string
		prog *ebpf.Program
	}{
		{"sched/sched_process_fork", ld.objs.TraceSchedProcessFork},
		{"sched/sched_process_exec", ld.objs.TraceSchedProcessExec},
		{"sched/sched_process_exit", ld.objs.TraceSchedProcessExit},
		{"syscalls/sys_enter_clone", ld.objs.TraceSysEnterClone},
	}

	kprobes := []struct {
		name string
		prog *ebpf.Program
	}{
		{"security_ptrace_access_check", ld.objs.KprobePtraceAccess},
		{"do_mount", ld.objs.KprobeDoMount},
		{"cgroup_attach_task", ld.objs.KprobeCgroupAttach},
		{"proc_reg", ld.objs.KprobeProcReg},
		{"cgroup_release_agent", ld.objs.KprobeCgroupReleaseAgent},
	}

	for _, tp := range tracepoints {
		if tp.prog == nil {
			continue
		}
		l, err := link.Tracepoint(tp.name[:4], tp.name[5:], tp.prog, nil)
		if err != nil {
			log.Printf("Warning: failed to attach tracepoint %s: %v", tp.name, err)
			continue
		}
		ld.links = append(ld.links, l)
		log.Printf("Attached tracepoint: %s", tp.name)
	}

	for _, kp := range kprobes {
		if kp.prog == nil {
			continue
		}
		l, err := link.Kprobe(kp.name, kp.prog, nil)
		if err != nil {
			log.Printf("Warning: failed to attach kprobe %s: %v", kp.name, err)
			continue
		}
		ld.links = append(ld.links, l)
		log.Printf("Attached kprobe: %s", kp.name)
	}

	return ld, nil
}

func (ld *BPFLoader) GetEventReader() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(ld.objs.Events)
}

func (ld *BPFLoader) Close() {
	for _, l := range ld.links {
		if err := l.Close(); err != nil {
			log.Printf("Error closing link: %v", err)
		}
	}
	if ld.objs.Events != nil {
		ld.objs.Events.Close()
	}
}
