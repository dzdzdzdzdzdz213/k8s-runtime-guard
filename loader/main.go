package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

type Config struct {
	LearningMode bool   `json:"learning_mode"`
	AutoKill     bool   `json:"auto_kill"`
	APIPort      int    `json:"api_port"`
	Kubeconfig   string `json:"kubeconfig"`
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("K8s Runtime Guard starting...")

	cfg := loadConfig()
	log.Printf("Config: learning=%v, auto_kill=%v, api_port=%d",
		cfg.LearningMode, cfg.AutoKill, cfg.APIPort)

	eng := NewEngine(cfg.LearningMode, cfg.AutoKill)

	bpfLoader, err := NewBPFLoader(eng)
	if err != nil {
		log.Fatalf("Failed to load BPF programs: %v", err)
	}
	defer bpfLoader.Close()
	log.Println("eBPF programs loaded and attached")

	procMon := NewProcessMonitor(bpfLoader, eng)
	go procMon.Start()

	api := NewAPIServer(cfg.APIPort, eng)
	go api.Start()
	log.Printf("API server listening on :%d", cfg.APIPort)

	if cfg.Kubeconfig != "" {
		watcher, err := NewAuditWatcher(cfg.Kubeconfig, eng)
		if err != nil {
			log.Printf("Warning: K8s audit watcher failed: %v", err)
		} else {
			go watcher.Start()
			log.Println("K8s audit watcher started")
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	bpfLoader.Close()
	api.Stop()
	log.Println("K8s Runtime Guard stopped")
}

func loadConfig() Config {
	cfg := Config{
		LearningMode: true,
		AutoKill:     false,
		APIPort:      9090,
		Kubeconfig:   "",
	}

	data, err := os.ReadFile("../config.json")
	if err != nil {
		data, err = os.ReadFile("config.json")
		if err != nil {
			log.Printf("No config file found, using defaults: %v", err)
			return cfg
		}
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("Invalid config, using defaults: %v", err)
	}
	return cfg
}

func init() {
	fmt.Println("K8s Runtime Guard v0.1.0")
	fmt.Println("Container-aware behavioral runtime security")
	fmt.Println("==========================================")
}
