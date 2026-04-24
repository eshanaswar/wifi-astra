package module

import (
	"os"
	"testing"
	"wifi-astra/internal/session"
)

func makePromptTestSession(t *testing.T) *session.Session {
	t.Helper()
	s, err := session.NewSession("prompt_test", t.TempDir())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { s.DB.Close() })
	return s
}

// Guard must return true immediately for modules that are not in the AP-adapter list.
// We pass nil for the DB — the switch returns before any DB access.
func TestAPAdapterGuardNonTargetModules(t *testing.T) {
	for _, id := range []string{"A1", "B3", "D1", "G4", "H1"} {
		m := &Module{ID: id, Name: "Test"}
		if !PromptAPAdapterGuard(nil, m) {
			t.Errorf("PromptAPAdapterGuard returned false for non-AP module %s; expected true (no-op)", id)
		}
	}
}

// Guard must return true without prompting when AP_INTERFACE is set in the DB.
func TestAPAdapterGuardSkipsWhenAPSet(t *testing.T) {
	s := makePromptTestSession(t)
	s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('AP_INTERFACE', 'wlan1')")

	for _, id := range []string{"F1", "F2", "F3", "D5"} {
		m := &Module{ID: id, Name: "Test Module"}
		if !PromptAPAdapterGuard(s.DB, m) {
			t.Errorf("PromptAPAdapterGuard returned false for %s when AP_INTERFACE is set; expected true", id)
		}
	}
}

// Guard must return true in headless mode without prompting, regardless of DB state.
func TestAPAdapterGuardSkipsInHeadlessMode(t *testing.T) {
	os.Setenv("ASTRA_HEADLESS", "true")
	defer os.Unsetenv("ASTRA_HEADLESS")

	s := makePromptTestSession(t)
	// DB has no AP_INTERFACE entry — would normally trigger the prompt

	for _, id := range []string{"F1", "F2", "F3", "D5"} {
		m := &Module{ID: id, Name: "Test Module"}
		if !PromptAPAdapterGuard(s.DB, m) {
			t.Errorf("PromptAPAdapterGuard returned false in headless mode for %s; expected true", id)
		}
	}
}
