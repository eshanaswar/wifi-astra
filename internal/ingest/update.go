package ingest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"wifi-astra/internal/logging"
)

// UpdateOUIDatabase downloads the latest OUI data from IEEE and updates the local data/oui.json file.
func UpdateOUIDatabase(dataDir string) error {
	url := "https://linuxnet.ca/ieee/oui.txt" // A cleaner version of the IEEE OUI list
	logging.Info("Downloading latest OUI data from %s...", url)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download OUI data: %v", err)
	}
	defer resp.Body.Close()

	newOUI := make(map[string]string)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: 00-00-00 (hex)  GENERATION COMPU-TECH CO., LTD.
		if strings.Contains(line, "(hex)") {
			parts := strings.Split(line, "(hex)")
			if len(parts) < 2 {
				continue
			}
			prefix := strings.TrimSpace(parts[0])
			prefix = strings.ReplaceAll(prefix, "-", ":")
			
			vendor := strings.TrimSpace(parts[1])
			if prefix != "" && vendor != "" {
				newOUI[prefix] = vendor
			}
		}
	}

	if len(newOUI) < 1000 {
		return fmt.Errorf("parsed OUI data seems too small (%d entries), aborting update", len(newOUI))
	}

	outputPath := filepath.Join(dataDir, "oui.json")
	// Ensure directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(newOUI); err != nil {
		return err
	}

	logging.Success("OUI database updated with %d entries. Saved to %s", len(newOUI), outputPath)
	logging.Info("Note: Restart the application to load the new database into memory.")
	return nil
}
