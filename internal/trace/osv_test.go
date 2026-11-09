package trace

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// TestQueryBatchSplitsBigProjectsIntoChunksOSVAccepts uses a local fake
// OSV.dev (net/http/httptest) that, like the real one, refuses more than
// osvBatchLimit queries in one request. 2,500 dependencies must go out as
// three requests (1000, 1000, 500) and come back as 2,500 results in the
// original order. Found 2026-11-09: a project with several lockfiles failed
// with "OSV.dev querybatch failed: 400 Bad Request".
func TestQueryBatchSplitsBigProjectsIntoChunksOSVAccepts(t *testing.T) {
	var sizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req queryBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if len(req.Queries) > osvBatchLimit {
			http.Error(w, "too many queries", http.StatusBadRequest)
			return
		}
		sizes = append(sizes, len(req.Queries))
		type vuln struct {
			ID string `json:"id"`
		}
		type res struct {
			Vulns []vuln `json:"vulns"`
		}
		out := struct {
			Results []res `json:"results"`
		}{}
		for _, q := range req.Queries {
			out.Results = append(out.Results, res{Vulns: []vuln{{ID: "ID-" + q.Package.Name}}})
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	old := osvAPIBase
	osvAPIBase = srv.URL
	defer func() { osvAPIBase = old }()

	deps := make([]discover.Dependency, 2500)
	for i := range deps {
		deps[i] = discover.Dependency{Name: fmt.Sprintf("pkg%d", i), Ecosystem: "npm", Version: "1.0.0"}
	}
	results, err := QueryBatch(deps)
	if err != nil {
		t.Fatalf("QueryBatch returned an error: %v", err)
	}
	if fmt.Sprint(sizes) != "[1000 1000 500]" {
		t.Errorf("request sizes = %v, want [1000 1000 500]", sizes)
	}
	if len(results) != 2500 || results[0][0] != "ID-pkg0" || results[1999][0] != "ID-pkg1999" || results[2499][0] != "ID-pkg2499" {
		t.Errorf("results out of order or missing: len=%d first=%v last=%v", len(results), results[0], results[len(results)-1])
	}
}
