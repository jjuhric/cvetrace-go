package trace

import (
	"testing"

	"github.com/jjuhric/cvetrace-go/internal/discover"
)

// These tests call the live OSV.dev API (https://osv.dev, no key required)
// against a package/version with a known, long-standing CVE, so they need
// network access -- the same approach the Node version of this tool uses.

func TestQueryBatchFindsTheKnownCVEForMinimist(t *testing.T) {
	deps := []discover.Dependency{{Name: "minimist", Ecosystem: "npm", Version: "0.0.8"}}

	results, err := QueryBatch(deps)
	if err != nil {
		t.Fatalf("QueryBatch returned an error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d result sets, want 1", len(results))
	}

	found := false
	for _, id := range results[0] {
		if id == "GHSA-vh95-rmgr-6w4m" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected GHSA-vh95-rmgr-6w4m among %v", results[0])
	}
}

func TestGetVulnDetailsReturnsTheAdvisoryRecordForAKnownID(t *testing.T) {
	detail, err := GetVulnDetails("GHSA-vh95-rmgr-6w4m")
	if err != nil {
		t.Fatalf("GetVulnDetails returned an error: %v", err)
	}

	if detail.ID != "GHSA-vh95-rmgr-6w4m" {
		t.Errorf("got id %q, want %q", detail.ID, "GHSA-vh95-rmgr-6w4m")
	}

	foundAlias := false
	for _, alias := range detail.Aliases {
		if alias == "CVE-2020-7598" {
			foundAlias = true
		}
	}
	if !foundAlias {
		t.Errorf("expected CVE-2020-7598 among aliases %v", detail.Aliases)
	}
}
