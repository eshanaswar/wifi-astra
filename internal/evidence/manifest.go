package evidence

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// AppendManifest computes the SHA256 of filePath and appends a line to
// manifestPath in the format: "<hex>  <basename>\n" (sha256sum-compatible).
// If filePath does not exist, the call is a no-op (no entry, no error).
func AppendManifest(manifestPath, filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}
	sum, err := sha256File(filePath)
	if err != nil {
		return fmt.Errorf("evidence: sha256 %s: %w", filePath, err)
	}
	line := fmt.Sprintf("%s  %s\n", sum, filepath.Base(filePath))
	f, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("evidence: open manifest: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("evidence: write manifest: %w", err)
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
