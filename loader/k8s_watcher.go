package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

type AuditEvent struct {
	Kind         string     `json:"kind"`
	APIVersion   string     `json:"apiVersion"`
	Level        string     `json:"level"`
	Stage        string     `json:"stage"`
	RequestURI   string     `json:"requestURI"`
	Verb         string     `json:"verb"`
	User         UserInfo   `json:"user"`
	ObjectRef    ObjectRef  `json:"objectRef,omitempty"`
	ResponseCode int        `json:"responseCode"`
	Timestamp    string     `json:"timestamp"`
}

type UserInfo struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type ObjectRef struct {
	Resource     string `json:"resource"`
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	Subresource  string `json:"subresource,omitempty"`
}

type AuditWatcher struct {
	engine        *Engine
	kubeconfig    string
	auditFilePath string
	lastOffset    int64
}

func NewAuditWatcher(kubeconfig string, engine *Engine) (*AuditWatcher, error) {
	aw := &AuditWatcher{
		engine:     engine,
		kubeconfig: kubeconfig,
	}
	if kubeconfig != "" {
		log.Printf("K8s audit watcher configured with kubeconfig: %s", kubeconfig)
	}
	return aw, nil
}

func (aw *AuditWatcher) Start() {
	log.Println("K8s audit watcher started (watching for exec/attach events)")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if aw.auditFilePath != "" {
			aw.parseAuditFile()
		}
	}
}

func (aw *AuditWatcher) parseAuditFile() {
	data, err := os.ReadFile(aw.auditFilePath)
	if err != nil {
		return
	}
	if int64(len(data)) <= aw.lastOffset {
		return
	}
	newData := data[aw.lastOffset:]
	aw.lastOffset = int64(len(data))

	var events []AuditEvent
	if err := json.Unmarshal(newData, &events); err != nil {
		return
	}
	for _, ev := range events {
		aw.processAuditEvent(ev)
	}
}

func (aw *AuditWatcher) processAuditEvent(ev AuditEvent) {
	if ev.ObjectRef.Resource == "pods" && ev.ObjectRef.Subresource == "exec" {
		alert := fmt.Sprintf(
			"K8s exec into pod %s/%s by user %s",
			ev.ObjectRef.Namespace, ev.ObjectRef.Name, ev.User.Username,
		)
		log.Printf("AUDIT: %s", alert)
		aw.engine.RaiseAlert(
			RuleK8sExecInPod,
			SeverityHigh,
			0, "kubectl", ev.ObjectRef.Name,
			alert,
			map[string]any{
				"namespace": ev.ObjectRef.Namespace,
				"pod":       ev.ObjectRef.Name,
				"username":  ev.User.Username,
			},
		)
	}
}

func (aw *AuditWatcher) SetAuditFile(path string) {
	aw.auditFilePath = path
	log.Printf("K8s audit file set to: %s", path)
}
