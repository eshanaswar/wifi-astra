package api

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"os"
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
}

func NewServer(database *sql.DB, socketPath string) *Server {
	return &Server{
		db:         database,
		state:      state.NewStateManager(database),
		supervisor: proc.NewSupervisor(),
		socketPath: socketPath,
	}
}

func (s *Server) Start() error {
	// Remove existing socket if any
	os.Remove(s.socketPath)

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}

	// Set permissions for the socket
	os.Chmod(s.socketPath, 0666)

	mux := http.NewServeMux()

	// --- State Endpoints ---
	mux.HandleFunc("/v1/config/get", s.handleGetConfig)
	mux.HandleFunc("/v1/config/set", s.handleSetConfig)
	mux.HandleFunc("/v1/config/batch-set", s.handleBatchSetConfig)
	mux.HandleFunc("/v1/status/get", s.handleGetStatus)
	mux.HandleFunc("/v1/status/set", s.handleUpdateStatus)
	mux.HandleFunc("/v1/status/batch-set", s.handleBatchUpdateStatus)

	// --- Ingest Endpoints ---
	mux.HandleFunc("/v1/ingest/airodump", s.handleIngestAirodump)
	mux.HandleFunc("/v1/ingest/network", s.handleIngestNetwork)
	mux.HandleFunc("/v1/ingest/client", s.handleIngestClient)
	mux.HandleFunc("/v1/ingest/batch-clients", s.handleBatchIngestClients)
	mux.HandleFunc("/v1/ingest/credential", s.handleIngestCredential)
	mux.HandleFunc("/v1/ingest/vulnerability", s.handleIngestVulnerability)

	// --- List Endpoints ---
	mux.HandleFunc("/v1/networks", s.handleListNetworks)
	mux.HandleFunc("/v1/networks/hidden", s.handleListHiddenNetworks)
	mux.HandleFunc("/v1/clients", s.handleListClients)
	mux.HandleFunc("/v1/credentials", s.handleListCredentials)
	mux.HandleFunc("/v1/vulnerabilities", s.handleListVulnerabilities)

	// --- Process Endpoints ---
	mux.HandleFunc("/v1/process/start", s.handleProcessStart)
	mux.HandleFunc("/v1/process/stop", s.handleProcessStop)
	mux.HandleFunc("/v1/process/list", s.handleProcessList)

	mux.HandleFunc("/v1/shutdown", s.handleShutdown)

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
