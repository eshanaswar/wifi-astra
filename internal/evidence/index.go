package evidence

import (
	"fmt"
	"os"
	"time"
)

// WriteIndex scans evidenceDir and writes a human-readable EVIDENCE_INDEX.txt
// at indexPath, listing every non-directory file with size and modification time.
// The index is overwritten on each call.
func WriteIndex(evidenceDir, indexPath string) error {
	entries, err := os.ReadDir(evidenceDir)
	if err != nil {
		return fmt.Errorf("evidence: read dir %s: %w", evidenceDir, err)
	}

	f, err := os.Create(indexPath)
	if err != nil {
		return fmt.Errorf("evidence: create index: %w", err)
	}
	defer f.Close()

	fmt.Fprintf(f, "Evidence Index — generated %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintln(f, "========================================")
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		fmt.Fprintf(f, "%-45s  %8d bytes  %s\n",
			e.Name(), info.Size(), info.ModTime().UTC().Format("2006-01-02 15:04:05"))
	}
	return nil
}
