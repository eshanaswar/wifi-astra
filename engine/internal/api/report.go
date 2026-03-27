package api

import (
	"html/template"
	"net/http"
	"os"
	"time"
	"wifi-astra/engine/internal/db"
)

type ReportData struct {
	SessionID       string
	SessionName     string
	GeneratedAt     string
	Configs         map[string]string
	Networks        []db.Network
	Clients         []db.Client
	Credentials     []db.Credential
	Vulnerabilities []db.Vulnerability
	Results         []db.TestResult
	Summary         struct {
		Total    int
		Done     int
		Findings int
		Critical int
		Secure   int
	}
}

const reportTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Assessment Report - {{.SessionID}}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f7f6; }
        .container { max-width: 1000px; margin: 20px auto; background: #fff; padding: 40px; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 8px; }
        h1, h2, h3 { color: #2c3e50; }
        .header { border-bottom: 2px solid #3498db; padding-bottom: 20px; margin-bottom: 30px; }
        .summary-box { display: flex; justify-content: space-between; margin-bottom: 30px; }
        .stat-card { background: #ecf0f1; padding: 20px; border-radius: 8px; text-align: center; flex: 1; margin: 0 10px; }
        .stat-val { font-size: 24px; font-weight: bold; color: #2980b9; }
        .stat-label { font-size: 14px; color: #7f8c8d; text-transform: uppercase; }
        .finding-critical { border-left: 5px solid #e74c3c; background: #fdf2f2; padding: 15px; margin-bottom: 10px; }
        .finding-info { border-left: 5px solid #3498db; background: #f2f9ff; padding: 15px; margin-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-critical { background: #e74c3c; color: #fff; }
        .badge-done { background: #27ae60; color: #fff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WiFi-Astra Assessment Report</h1>
            <p>Session: <strong>{{.SessionName}}</strong> ({{.SessionID}})</p>
            <p>Generated: {{.GeneratedAt}}</p>
        </div>

        <div class="summary-box">
            <div class="stat-card"><div class="stat-val">{{.Summary.Done}}/{{.Summary.Total}}</div><div class="stat-label">Tests Run</div></div>
            <div class="stat-card"><div class="stat-val">{{.Summary.Findings}}</div><div class="stat-label">Findings</div></div>
            <div class="stat-card"><div class="stat-val" style="color: #e74c3c;">{{.Summary.Critical}}</div><div class="stat-label">Critical</div></div>
        </div>

        <h2>Executive Summary</h2>
        <p>The security assessment of the target wireless environment has identified <strong>{{.Summary.Findings}}</strong> potential vulnerabilities, of which <strong>{{.Summary.Critical}}</strong> are classified as CRITICAL.</p>

        <h2>Discovered Infrastructure</h2>
        <table>
            <thead><tr><th>BSSID</th><th>SSID</th><th>CH</th><th>Encryption</th><th>Signal</th></tr></thead>
            <tbody>
                {{range .Networks}}
                <tr><td><code>{{.BSSID}}</code></td><td>{{if .SSID}}{{.SSID}}{{else}}<em>&lt;HIDDEN&gt;</em>{{end}}</td><td>{{.Channel}}</td><td>{{.Encryption}}</td><td>{{.Signal}}dBm</td></tr>
                {{end}}
            </tbody>
        </table>

        <h2>Detailed Test Results</h2>
        {{range .Results}}
        <div class="finding-{{if eq .Status "done"}}info{{else}}critical{{end}}">
            <h3>[{{.TCID}}] {{.Status}}</h3>
            <p><strong>Duration:</strong> {{.DurationSec}}s | <strong>Exit Code:</strong> {{.ExitCode}}</p>
        </div>
        {{end}}
    </div>
</body>
</html>
`

func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	outputPath := r.URL.Query().Get("output")
	if outputPath == "" {
		http.Error(w, "output parameter required", http.StatusBadRequest)
		return
	}

	data := ReportData{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
	}

	configs, _ := s.state.GetAllConfigs()
	data.Configs = configs
	data.SessionID = configs["session_id"]
	data.SessionName = configs["session_name"]

	data.Networks, _ = db.ListNetworks(s.db)
	data.Clients, _ = db.ListClients(s.db)
	data.Credentials, _ = db.ListCredentials(s.db)
	data.Vulnerabilities, _ = db.ListVulnerabilities(s.db)
	data.Results, _ = db.GetTestResults(s.db)

	// Calculate summary
	data.Summary.Total = 42 // Constant for now
	data.Summary.Done = len(data.Results)
	for _, res := range data.Results {
		if res.Status == "failed" {
			data.Summary.Findings++
		}
	}
	for _, v := range data.Vulnerabilities {
		data.Summary.Findings++
		if v.Severity == "CRITICAL" {
			data.Summary.Critical++
		}
	}

	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	f, err := os.Create(outputPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Report generated successfully"))
}
