// pkg/prereq/prereq_test.go
package prereq_test

import (
	"testing"

	"wifi-astra/pkg/prereq"
)

func TestPreflightModulesKnownAvailable(t *testing.T) {
	// "true" is always available on any Unix system
	available := prereq.PreflightModules(map[string][]string{
		"X1": {"true"},
		"X2": {"true", "true"},
	})
	for _, id := range []string{"X1", "X2"} {
		if !available[id] {
			t.Errorf("expected module %s to be available", id)
		}
	}
}

func TestPreflightModulesMissingTool(t *testing.T) {
	available := prereq.PreflightModules(map[string][]string{
		"Y1": {"this-tool-definitely-does-not-exist-12345"},
		"Y2": {"true"},
	})
	if available["Y1"] {
		t.Error("Y1 should be unavailable — its tool is missing")
	}
	if !available["Y2"] {
		t.Error("Y2 should be available — 'true' is always present")
	}
}
