package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
	"wifi-astra/internal/db"
	"wifi-astra/internal/session"
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
        .container { max-width: 1100px; margin: 20px auto; background: #fff; padding: 40px; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 8px; }
        h1, h2, h3 { color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-top: 40px; }
        .header { border-bottom: 3px solid #3498db; padding-bottom: 20px; margin-bottom: 30px; }
        .summary-box { display: flex; justify-content: space-between; margin-bottom: 30px; }
        .stat-card { background: #ecf0f1; padding: 20px; border-radius: 8px; text-align: center; flex: 1; margin: 0 10px; }
        .stat-val { font-size: 28px; font-weight: bold; color: #2980b9; }
        .stat-label { font-size: 14px; color: #7f8c8d; text-transform: uppercase; letter-spacing: 1px; }
        .finding-critical { border-left: 5px solid #e74c3c; background: #fdf2f2; padding: 15px; margin-bottom: 10px; border-radius: 0 4px 4px 0; }
        .finding-high { border-left: 5px solid #e67e22; background: #fff5eb; padding: 15px; margin-bottom: 10px; border-radius: 0 4px 4px 0; }
        .finding-medium { border-left: 5px solid #f39c12; background: #fffbf0; padding: 15px; margin-bottom: 10px; border-radius: 0 4px 4px 0; }
        .finding-info { border-left: 5px solid #3498db; background: #f2f9ff; padding: 15px; margin-bottom: 10px; border-radius: 0 4px 4px 0; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 30px; font-size: 14px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
        th { background-color: #f8f9fa; color: #7f8c8d; text-transform: uppercase; font-size: 12px; }
        tr:hover { background-color: #fcfcfc; }
        code { background: #f0f0f0; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .badge-critical { background: #e74c3c; color: #fff; }
        .badge-high { background: #e67e22; color: #fff; }
        .badge-done { background: #27ae60; color: #fff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ WiFi-Astra Security Assessment</h1>
            <p>Session: <strong>{{.SessionName}}</strong> (<code>{{.SessionID}}</code>)</p>
            <p>Generated: {{.GeneratedAt}}</p>
        </div>

        <div class="summary-box">
            <div class="stat-card"><div class="stat-val">{{.Summary.Done}}/{{.Summary.Total}}</div><div class="stat-label">Tests Run</div></div>
            <div class="stat-card"><div class="stat-val">{{.Summary.Findings}}</div><div class="stat-label">Total Findings</div></div>
            <div class="stat-card"><div class="stat-val" style="color: #e74c3c;">{{.Summary.Critical}}</div><div class="stat-label">Critical Risks</div></div>
            <div class="stat-card"><div class="stat-val" style="color: #27ae60;">{{.Summary.Secure}}</div><div class="stat-label">Modules Secure</div></div>
        </div>

        <h2>Executive Summary</h2>
        <p>The security assessment of the wireless environment has concluded with <strong>{{.Summary.Findings}}</strong> total findings. 
           <strong>{{.Summary.Critical}}</strong> vulnerabilities require immediate remediation.</p>

        {{if .Vulnerabilities}}
        <h2>Identified Vulnerabilities</h2>
        {{range .Vulnerabilities}}
        <div class="finding-{{if eq .Severity "CRITICAL"}}critical{{else if eq .Severity "HIGH"}}high{{else if eq .Severity "MEDIUM"}}medium{{else}}info{{end}}">
            <h3>{{.Name}} <span class="badge badge-{{lower .Severity}}">{{.Severity}}</span></h3>
            <p><strong>Target:</strong> <code>{{.TargetHost}}</code> | <strong>Detected via:</strong> {{.TCID}}</p>
            <p>{{.Description}}</p>
            {{if .Rationale}}<p><strong>Rationale:</strong> <em>{{.Rationale}}</em></p>{{end}}
            {{if .Remediation}}<p><strong>Remediation:</strong> {{.Remediation}}</p>{{end}}
            {{if .EvidenceFile}}<p><strong>Evidence:</strong> <a href="../evidence/{{base .EvidenceFile}}"><code>{{base .EvidenceFile}}</code></a></p>{{end}}
        </div>
        {{end}}
        {{end}}

        {{if .Credentials}}
        <h2>Captured Credentials</h2>
        <table>
            <thead><tr><th>Module</th><th>Protocol</th><th>Target</th><th>Username</th><th>Password / Hash</th><th>Rationale</th><th>Evidence</th></tr></thead>
            <tbody>
                {{range .Credentials}}
                <tr><td>{{.TCID}}</td><td><span class="badge">{{.Proto}}</span></td><td><code>{{.TargetHost}}</code></td><td><strong>{{.Username}}</strong></td><td><code>{{if .Password}}{{.Password}}{{else}}{{.Hash}}{{end}}</code></td><td>{{.Rationale}}</td><td>{{if .EvidenceFile}}<a href="../evidence/{{base .EvidenceFile}}">View</a>{{else}}-{{end}}</td></tr>
                {{end}}
            </tbody>
        </table>
        {{end}}

        <h2>Discovered Infrastructure</h2>
        <table>
            <thead><tr><th>BSSID</th><th>SSID</th><th>CH</th><th>Encryption</th><th>Signal</th><th>Beacons</th></tr></thead>
            <tbody>
                {{range .Networks}}
                <tr><td><code>{{.BSSID}}</code></td><td>{{if .SSID}}{{.SSID}}{{else}}<em>&lt;HIDDEN&gt;</em>{{end}}</td><td>{{.Channel}}</td><td>{{.Encryption}}</td><td>{{.Signal}}dBm</td><td>{{.Beacons}}</td></tr>
                {{end}}
            </tbody>
        </table>

        {{if .Clients}}
        <h2>Discovered Clients</h2>
        <table>
            <thead><tr><th>MAC Address</th><th>Vendor</th><th>IP Address</th><th>Hostname</th><th>Last AP</th></tr></thead>
            <tbody>
                {{range .Clients}}
                <tr><td><code>{{.MAC}}</code></td><td>{{.Vendor}}</td><td>{{.IP}}</td><td>{{.Hostname}}</td><td><code>{{.LastBSSID}}</code></td></tr>
                {{end}}
            </tbody>
        </table>
        {{end}}

        <h2>Module Execution Log</h2>
        <table>
            <thead><tr><th>ID</th><th>Status</th><th>Duration</th><th>Replication Command</th></tr></thead>
            <tbody>
                {{range .Results}}
                <tr>
                    <td><strong>{{.TCID}}</strong></td>
                    <td><span class="badge badge-done">{{.Status}}</span></td>
                    <td>{{.DurationSec}}s</td>
                    <td><code>{{.CommandRun}}</code></td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>
`

func buildReportData(s *session.Session) ReportData {
	data := ReportData{
		SessionID:   s.ID,
		SessionName: s.Name,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Configs:     make(map[string]string),
	}

	// Load Configs
	rows, _ := s.DB.Query("SELECT key, value FROM config")
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		data.Configs[k] = v
	}
	rows.Close()

	data.Networks, _ = db.ListNetworks(s.DB)
	data.Clients, _ = db.ListClients(s.DB)
	data.Credentials, _ = db.ListCredentials(s.DB)
	data.Vulnerabilities, _ = db.ListVulnerabilities(s.DB)
	data.Results, _ = db.GetTestResults(s.DB)

	// Calculate summary — total module count from filesystem
	modDir := "./modules"
	if val, ok := data.Configs["mod_dir"]; ok {
		modDir = val
	}
	entries, _ := os.ReadDir(modDir)
	modCount := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sh") {
			modCount++
		}
	}

	data.Summary.Total = modCount
	data.Summary.Done = len(data.Results)

	// Bug 1 fix: only count actual vulnerability records as findings, not failed runs
	for _, v := range data.Vulnerabilities {
		data.Summary.Findings++
		if v.Severity == "CRITICAL" {
			data.Summary.Critical++
		}
	}
	data.Summary.Findings += len(data.Credentials)

	// Bug 2 fix: compute Secure = completed modules with zero non-INFO findings
	completedModules := make(map[string]bool)
	for _, res := range data.Results {
		if res.Status == "completed" {
			completedModules[res.TCID] = true
		}
	}
	moduleFindings := make(map[string]bool)
	for _, v := range data.Vulnerabilities {
		if v.Severity != "INFO" {
			moduleFindings[v.TCID] = true
		}
	}
	for tcID := range completedModules {
		if !moduleFindings[tcID] {
			data.Summary.Secure++
		}
	}

	return data
}

// GenerateMarkdownReport writes assessment_report.md alongside the HTML report.
func GenerateMarkdownReport(s *session.Session) (string, error) {
	data := buildReportData(s)

	var sb strings.Builder

	sb.WriteString("# WiFi-Astra Security Assessment\n\n")
	sb.WriteString(fmt.Sprintf("**Session:** %s (`%s`)  \n", data.SessionName, data.SessionID))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n\n", data.GeneratedAt))

	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Value |\n|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Tests Run | %d / %d |\n", data.Summary.Done, data.Summary.Total))
	sb.WriteString(fmt.Sprintf("| Total Findings | %d |\n", data.Summary.Findings))
	sb.WriteString(fmt.Sprintf("| Critical Risks | %d |\n", data.Summary.Critical))
	sb.WriteString(fmt.Sprintf("| Modules Secure | %d |\n\n", data.Summary.Secure))

	if len(data.Vulnerabilities) > 0 {
		sb.WriteString("## Vulnerabilities\n\n")
		for _, v := range data.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("### [%s] %s\n\n", v.Severity, v.Name))
			sb.WriteString(fmt.Sprintf("- **Module:** %s\n", v.TCID))
			sb.WriteString(fmt.Sprintf("- **Target:** `%s`\n", v.TargetHost))
			if v.Description != "" {
				sb.WriteString(fmt.Sprintf("- **Description:** %s\n", v.Description))
			}
			if v.Rationale != "" {
				sb.WriteString(fmt.Sprintf("- **Rationale:** %s\n", v.Rationale))
			}
			if v.Remediation != "" {
				sb.WriteString(fmt.Sprintf("- **Remediation:** %s\n", v.Remediation))
			}
			if v.EvidenceFile != "" {
				sb.WriteString(fmt.Sprintf("- **Evidence:** `%s`\n", filepath.Base(v.EvidenceFile)))
			}
			sb.WriteString("\n")
		}
	}

	if len(data.Credentials) > 0 {
		sb.WriteString("## Captured Credentials\n\n")
		sb.WriteString("| Module | Protocol | Target | Username | Secret |\n")
		sb.WriteString("|--------|----------|--------|----------|--------|\n")
		for _, cred := range data.Credentials {
			secret := cred.Hash
			if cred.Password != "" {
				secret = cred.Password
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | `%s` | **%s** | `%s` |\n",
				cred.TCID, cred.Proto, cred.TargetHost, cred.Username, secret))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Discovered Networks\n\n")
	sb.WriteString("| BSSID | SSID | CH | Encryption | Signal |\n")
	sb.WriteString("|-------|------|----|------------|--------|\n")
	for _, n := range data.Networks {
		ssid := n.SSID
		if ssid == "" {
			ssid = "*HIDDEN*"
		}
		sb.WriteString(fmt.Sprintf("| `%s` | %s | %d | %s | %ddBm |\n",
			n.BSSID, ssid, n.Channel, n.Encryption, n.Signal))
	}
	sb.WriteString("\n")

	if len(data.Results) > 0 {
		sb.WriteString("## Module Execution Log\n\n")
		sb.WriteString("| Module | Status | Duration |\n")
		sb.WriteString("|--------|--------|----------|\n")
		for _, r := range data.Results {
			sb.WriteString(fmt.Sprintf("| %s | %s | %ds |\n", r.TCID, r.Status, r.DurationSec))
		}
		sb.WriteString("\n")
	}

	outputPath := filepath.Join(s.ReportDir, "assessment_report.md")
	if err := os.WriteFile(outputPath, []byte(sb.String()), 0644); err != nil {
		return "", err
	}
	return outputPath, nil
}

func GenerateReport(s *session.Session) (string, error) {
	data := buildReportData(s)

	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"base":  filepath.Base,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(reportTemplate)
	if err != nil {
		return "", err
	}

	outputPath := filepath.Join(s.ReportDir, "assessment_report.html")
	f, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return "", err
	}

	return outputPath, nil
}
