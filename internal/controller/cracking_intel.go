package controller

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GenerateSSIDWordlist writes a file of SSID-derived password candidates to outputPath.
// Returns an error if ssid is empty (caller skips Stage 1) or the file cannot be written.
func GenerateSSIDWordlist(ssid, outputPath string) error {
	if ssid == "" {
		return fmt.Errorf("ssid is empty: cannot generate mutation wordlist")
	}

	lower := strings.ToLower(ssid)
	upper := strings.ToUpper(ssid)
	title := strings.ToUpper(ssid[:1]) + strings.ToLower(ssid[1:])

	suffixes := []string{
		"", "1", "01", "123", "1234", "12345",
		"2024", "2025", "2026",
		"!", "#1", "@1",
	}

	seen := map[string]bool{}
	var candidates []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			candidates = append(candidates, s)
		}
	}

	for _, base := range []string{ssid, lower, upper, title} {
		for _, suf := range suffixes {
			add(base + suf)
		}
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create wordlist: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, c := range candidates {
		fmt.Fprintln(w, c)
	}
	return w.Flush()
}

// CommonWordlistPaths returns paths to discovered rockyou wordlist files, in priority order.
// Only paths that exist and are regular files are returned. Empty slice is valid.
func CommonWordlistPaths() []string {
	candidates := []string{
		"/usr/share/wordlists/rockyou.txt",
		"/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
		"/opt/wordlists/rockyou.txt",
	}
	found := []string{}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			found = append(found, p)
		}
	}
	return found
}

// BestRulePath returns the path to best64.rule if found at a standard hashcat location,
// or "" if not found. Callers should pass nil rules to RunHashcat when this returns "".
func BestRulePath() string {
	candidates := []string{
		"/usr/share/hashcat/rules/best64.rule",
		"/usr/lib/hashcat/rules/best64.rule",
		"/usr/local/share/hashcat/rules/best64.rule",
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// commonRulesetForWordlist returns the best64 rule path as a single-element slice,
// or nil if best64.rule is not installed. Use as the rules arg to RunHashcat.
func commonRulesetForWordlist() []string {
	if r := BestRulePath(); r != "" {
		return []string{r}
	}
	return nil
}

// ssidWordlistPath returns the evidence path for the SSID mutation wordlist.
func ssidWordlistPath(evidenceDir string) string {
	return filepath.Join(evidenceDir, "D1_ssid_wordlist.txt")
}
