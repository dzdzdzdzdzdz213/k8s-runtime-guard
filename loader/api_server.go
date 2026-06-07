package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type APIServer struct {
	port   int
	engine *Engine
	server *http.Server
}

func NewAPIServer(port int, engine *Engine) *APIServer {
	return &APIServer{
		port:   port,
		engine: engine,
	}
}

func (api *APIServer) Start() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", api.handleHealth)
	mux.HandleFunc("/api/v1/stats", api.handleStats)
	mux.HandleFunc("/api/v1/alerts", api.handleAlerts)
	mux.HandleFunc("/api/v1/containers", api.handleContainers)
	mux.HandleFunc("/api/v1/processes", api.handleProcessTree)
	mux.HandleFunc("/api/v1/config", api.handleConfig)
	mux.HandleFunc("/api/v1/events", api.handleSSE)

	api.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", api.port),
		Handler: withCORS(mux),
	}

	if err := api.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("API server error: %v", err)
	}
}

func (api *APIServer) Stop() {
	if api.server != nil {
		api.server.Close()
	}
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (api *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (api *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := api.engine.GetStats()
	api.engine.mu.RLock()
	stats.UptimeSeconds = 0
	api.engine.mu.RUnlock()
	jsonResponse(w, stats)
}

func (api *APIServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}

	alerts := api.engine.GetAlerts()
	if len(alerts) > limit {
		alerts = alerts[len(alerts)-limit:]
	}

	jsonResponse(w, map[string]any{
		"total":  api.engine.GetStats().TotalAlerts,
		"alerts": alerts,
	})
}

func (api *APIServer) handleContainers(w http.ResponseWriter, r *http.Request) {
	containers := api.engine.GetContainers()
	jsonResponse(w, map[string]any{
		"total":      len(containers),
		"containers": containers,
	})
}

func (api *APIServer) handleProcessTree(w http.ResponseWriter, r *http.Request) {
	processes := api.engine.GetProcessTree()
	jsonResponse(w, map[string]any{
		"total":    len(processes),
		"processes": processes,
	})
}

func (api *APIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var req struct {
			LearningMode *bool `json:"learning_mode"`
			AutoKill     *bool `json:"auto_kill"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if req.LearningMode != nil {
				api.engine.SetLearningMode(*req.LearningMode)
			}
			if req.AutoKill != nil {
				api.engine.autoKill = *req.AutoKill
			}
		}
	}

	api.engine.mu.RLock()
	defer api.engine.mu.RUnlock()
	jsonResponse(w, map[string]bool{
		"learning_mode": api.engine.learningMode,
		"auto_kill":     api.engine.autoKill,
	})
}

type SSEClient struct {
	ch    chan []byte
	done  chan struct{}
}

type SSEBroker struct {
	mu      sync.RWMutex
	clients map[string]*SSEClient
}

var broker = &SSEBroker{
	clients: make(map[string]*SSEClient),
}

func (api *APIServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	clientID := fmt.Sprintf("client-%d", time.Now().UnixNano())
	client := &SSEClient{
		ch:   make(chan []byte, 100),
		done: make(chan struct{}),
	}

	broker.mu.Lock()
	broker.clients[clientID] = client
	broker.mu.Unlock()

	defer func() {
		broker.mu.Lock()
		delete(broker.clients, clientID)
		broker.mu.Unlock()
	}()

	notify := r.Context().Done()

	for {
		select {
		case <-notify:
			return
		case msg := <-client.ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}
