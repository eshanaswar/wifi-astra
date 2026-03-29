package ingest

import (
	"database/sql"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"wifi-astra/internal/logging"
)

func init() {
	// Register for Category B (Internal Recon)
	RegisterParser("B", func(db *sql.DB, tcID string, evidenceDir string) error {
		xmlFile := filepath.Join(evidenceDir, strings.ToLower(tcID)+"_results.xml")
		if _, err := os.Stat(xmlFile); os.IsNotExist(err) {
			return nil
		}
		return IngestNmapXML(db, tcID, xmlFile)
	})
}

type NmapRun struct {
	Hosts []struct {
		Status struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
			Vendor   string `xml:"vendor,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostnames>hostname"`
		Ports []struct {
			PortId   string `xml:"portid,attr"`
			Protocol string `xml:"protocol,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
				Extra   string `xml:"extrainfo,attr"`
			} `xml:"service"`
			Scripts []struct {
				ID     string `xml:"id,attr"`
				Output string `xml:"output,attr"`
			} `xml:"script"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// IngestNmapXML parses an Nmap XML file and updates the database with high-detail findings.
func IngestNmapXML(database *sql.DB, tcID, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	var run NmapRun
	if err := xml.NewDecoder(f).Decode(&run); err != nil {
		return err
	}

	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}

		var ip4, ip6, mac, vendor string
		for _, addr := range host.Addresses {
			switch addr.AddrType {
			case "ipv4":
				ip4 = addr.Addr
			case "ipv6":
				ip6 = addr.Addr
			case "mac":
				mac = addr.Addr
				vendor = addr.Vendor
			}
		}

		// Use IPv4 as primary IP for now, fallback to IPv6
		primaryIP := ip4
		if primaryIP == "" { primaryIP = ip6 }

		hostnames := []string{}
		for _, h := range host.Hostnames {
			if h.Name != "" {
				hostnames = append(hostnames, h.Name)
			}
		}
		hostname := strings.Join(hostnames, ", ")

		if mac != "" {
			_, err = database.Exec(`UPDATE client SET ip = ?, hostname = ?, vendor = CASE WHEN vendor IS NULL OR vendor = '' THEN ? ELSE vendor END WHERE mac = ?`, 
				primaryIP, hostname, vendor, mac)
			if err != nil {
				logging.Error("Failed to update client from Nmap: %v", err)
			}
		}

		// Port & Service Ingestion
		for _, port := range host.Ports {
			if port.State.State == "open" {
				serviceDesc := port.Service.Name
				if port.Service.Product != "" {
					serviceDesc += " (" + port.Service.Product + " " + port.Service.Version + ")"
				}
				if port.Service.Extra != "" {
					serviceDesc += " [" + port.Service.Extra + "]"
				}

				// Record as Vulnerability (Exposed Service)
				database.Exec(`INSERT INTO vulnerability (tc_id, target_host, name, severity, description) 
					VALUES (?, ?, ?, ?, ?)`, 
					tcID, primaryIP, "Exposed Service", "INFO", "Port "+port.PortId+"/"+port.Protocol+" - "+serviceDesc)

				// Process NSE script outputs
				for _, script := range port.Scripts {
					severity := "LOW"
					if strings.Contains(strings.ToLower(script.Output), "vulnerable") || strings.Contains(strings.ToLower(script.Output), "exploit") {
						severity = "HIGH"
					}
					
					database.Exec(`INSERT INTO vulnerability (tc_id, target_host, name, severity, description) 
						VALUES (?, ?, ?, ?, ?)`, 
						tcID, primaryIP, "NSE Finding: "+script.ID, severity, script.Output)
				}
			}
		}
	}

	return nil
}
