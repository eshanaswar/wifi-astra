package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"wifi-astra/engine/internal/db"
	"wifi-astra/engine/internal/ingest"
	"wifi-astra/engine/internal/proc"
	"wifi-astra/engine/internal/state"
)

type Server struct {
	db         *sql.DB
	state      *state.StateManager
	supervisor *proc.Supervisor
	socketPath string
	server     *http.Server
	apiToken   string
}

func NewServer(database *sql.DB, socketPath string) *Server {
	return &Server{
		db:         database,
		state:      state.NewStateManager(database),
		supervisor: proc.NewSupervisor(),
		socketPath: socketPath,
	}
}

func (s *Server) generateToken() error {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return err
	}
	s.apiToken = hex.EncodeToString(b)
	
	// Save token to a file in the same directory as the socket
	tokenPath := filepath.Join(filepath.Dir(s.socketPath), "engine.token")
	if err := os.WriteFile(tokenPath, []byte(s.apiToken), 0600); err != nil {
		return fmt.Errorf("failed to save API token: %v", err)
	}
	fmt.Printf("API Token saved to: %s\n", tokenPath)
	return nil
}

func (s *Server) Start() error {
	if err := s.generateToken(); err != nil {
		return err
	}

	// Remove existing socket if any
	os.Remove(s.socketPath)

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}

	// Set permissions for the socket: 0600 (Owner only)
	// This is critical to prevent local users from accessing the root API
	os.Chmod(s.socketPath, 0600)

	mux := http.NewServeMux()

	// --- Middleware for Token Verification ---
	authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Astra-Token")
			if token != s.apiToken {
				http.Error(w, "Unauthorized: Invalid or missing Astra Token", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	// --- State Endpoints ---
	mux.HandleFunc("/v1/config/get", authMiddleware(s.handleGetConfig))
	mux.HandleFunc("/v1/config/set", authMiddleware(s.handleSetConfig))
	mux.HandleFunc("/v1/config/batch-set", authMiddleware(s.handleBatchSetConfig))
	mux.HandleFunc("/v1/status/get", authMiddleware(s.handleGetStatus))
	mux.HandleFunc("/v1/status/set", authMiddleware(s.handleUpdateStatus))
	mux.HandleFunc("/v1/status/batch-set", authMiddleware(s.handleBatchUpdateStatus))
	mux.HandleFunc("/v1/status/summary", authMiddleware(s.handleStatusSummary))

	// --- Ingest Endpoints ---
	mux.HandleFunc("/v1/ingest/airodump", authMiddleware(s.handleIngestAirodump))
	mux.HandleFunc("/v1/ingest/network", authMiddleware(s.handleIngestNetwork))
	mux.HandleFunc("/v1/ingest/client", authMiddleware(s.handleIngestClient))
	mux.HandleFunc("/v1/ingest/batch-clients", authMiddleware(s.handleBatchIngestClients))
	mux.HandleFunc("/v1/ingest/credential", authMiddleware(s.handleIngestCredential))
	mux.HandleFunc("/v1/ingest/vulnerability", authMiddleware(s.handleIngestVulnerability))

	// --- List Endpoints ---
	mux.HandleFunc("/v1/networks", authMiddleware(s.handleListNetworks))
	mux.HandleFunc("/v1/networks/hidden", authMiddleware(s.handleListHiddenNetworks))
	mux.HandleFunc("/v1/clients", authMiddleware(s.handleListClients))
	mux.HandleFunc("/v1/credentials", authMiddleware(s.handleListCredentials))
	mux.HandleFunc("/v1/vulnerabilities", authMiddleware(s.handleListVulnerabilities))

	// --- Process Endpoints ---
	mux.HandleFunc("/v1/process/start", authMiddleware(s.handleProcessStart))
	mux.HandleFunc("/v1/process/stop", authMiddleware(s.handleProcessStop))
	mux.HandleFunc("/v1/process/list", authMiddleware(s.handleProcessList))

	mux.HandleFunc("/v1/shutdown", authMiddleware(s.handleShutdown))

	server := &http.Server{Handler: mux}
	s.server = server
	return server.Serve(listener)
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Shutting down..."))
	go func() {
		s.Cleanup()
		os.Exit(0)
	}()
}

func (s *Server) Cleanup() {
	s.supervisor.Cleanup()
	os.Remove(s.socketPath)
}

// --- Handlers ---

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	val, err := s.state.GetConfig(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(val))
}

func (s *Server) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	val := r.URL.Query().Get("value")
	if err := s.state.SetConfig(key, val); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBatchSetConfig(w http.ResponseWriter, r *http.Request) {
	var configs map[string]string
	if err := json.NewDecoder(r.Body).Decode(&configs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for k, v := range configs {
		s.state.SetConfig(k, v)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	tc := r.URL.Query().Get("tc")
	status, err := s.state.GetModuleStatus(tc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(status))
}

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	tc := r.URL.Query().Get("tc")
	st := r.URL.Query().Get("status")
	if err := s.state.UpdateModuleStatus(tc, st, 0); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBatchUpdateStatus(w http.ResponseWriter, r *http.Request) {
	var statuses map[string]string
	if err := json.NewDecoder(r.Body).Decode(&statuses); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for k, v := range statuses {
		s.state.UpdateModuleStatus(k, v, 0)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleStatusSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.state.GetStatusSummary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(summary)
}

func (s *Server) handleIngestAirodump(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	if err := ingest.IngestAirodumpCSV(s.db, file); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleIngestNetwork(w http.ResponseWriter, r *http.Request) {
	var n db.Network
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO network (bssid, ssid, channel, encryption, signal, beacons, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);`,
		n.BSSID, n.SSID, n.Channel, n.Encryption, n.Signal, n.Beacons)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleIngestClient(w http.ResponseWriter, r *http.Request) {
	var c db.Client
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO client (mac, vendor, ip, hostname, last_signal, last_bssid, os_guess, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);`,
		c.MAC, c.Vendor, c.IP, c.Hostname, c.LastSignal, c.LastBSSID, c.OSGuess)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBatchIngestClients(w http.ResponseWriter, r *http.Request) {
	var clients []db.Client
	if err := json.NewDecoder(r.Body).Decode(&clients); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tx, _ := s.db.Begin()
	for _, c := range clients {
		tx.Exec(`INSERT OR REPLACE INTO client (mac, vendor, ip, hostname, last_signal, last_bssid, os_guess, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);`,
			c.MAC, c.Vendor, c.IP, c.Hostname, c.LastSignal, c.LastBSSID, c.OSGuess)
	}
	tx.Commit()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleIngestCredential(w http.ResponseWriter, r *http.Request) {
	var c db.Credential
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := s.db.Exec(`INSERT INTO credential (tc_id, client_mac, target_host, username, password, hash, proto)
		VALUES (?, ?, ?, ?, ?, ?, ?);`,
		c.TCID, c.ClientMAC, c.TargetHost, c.Username, c.Password, c.Hash, c.Proto)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleIngestVulnerability(w http.ResponseWriter, r *http.Request) {
	var v db.Vulnerability
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := s.db.Exec(`INSERT INTO vulnerability (tc_id, client_mac, target_host, name, severity, description, remediation)
		VALUES (?, ?, ?, ?, ?, ?, ?);`,
		v.TCID, v.ClientMAC, v.TargetHost, v.Name, v.Severity, v.Description, v.Remediation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	networks, err := db.ListNetworks(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(networks)
}

func (s *Server) handleListHiddenNetworks(w http.ResponseWriter, r *http.Request) {
	networks, err := db.ListNetworks(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var hidden []db.Network
	for _, n := range networks {
		if n.SSID == "" || n.SSID == "<HIDDEN>" {
			hidden = append(hidden, n)
		}
	}
	json.NewEncoder(w).Encode(hidden)
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := db.ListClients(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(clients)
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := db.ListCredentials(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(creds)
}

func (s *Server) handleListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	vulns, err := db.ListVulnerabilities(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(vulns)
}

func (s *Server) handleProcessStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      string   `json:"id"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
		LogFile string   `json:"log_file"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p, err := s.supervisor.StartProcess(req.ID, req.Command, req.Args, req.LogFile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(p)
}

func (s *Server) handleProcessStop(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if err := s.supervisor.StopProcess(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleProcessList(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(s.supervisor.ListProcesses())
}
