// Package trace batch-queries OSV.dev (https://osv.dev, no API key required)
// for known vulnerabilities affecting each dependency internal/discover
// found, and merges the results into Vulnerability values ready to report.
package trace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jjuhric/cvetrace-go/internal/discover"
)

// osvAPIBase is a var (not a const) only so tests can point it at a local
// fake server; nothing in the tool itself changes it.
var osvAPIBase = "https://api.osv.dev/v1"

// osvBatchLimit is OSV.dev's documented maximum number of queries in one
// /querybatch request. A bigger request is refused with "400 Bad Request", so a
// project with more dependencies than this (several lockfiles, a monorepo) is
// sent in chunks of at most this many and the answers are joined back in order.
var osvBatchLimit = 1000

// The types below mirror only the parts of OSV.dev's JSON shapes this
// project actually reads -- see https://google.github.io/osv.dev/api/.
// encoding/json ignores any JSON fields that aren't declared in a struct, so
// there's no need to model the entire API response.

type packageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type queryBatchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchQuery struct {
	Package packageRef `json:"package"`
	Version string     `json:"version"`
}

type queryBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// QueryBatch asks OSV.dev which known vulnerability ids affect each of the
// given dependencies, returning one []string of ids per dependency, in the
// same order the dependencies were passed in (an empty slice means "no known
// vulnerabilities for this one").
//
// Go note: net/http's functions always return a response *and* an error --
// always check the error first. A failed request (e.g. no network) has no
// usable response to read, so touching resp before checking err can panic.
func QueryBatch(deps []discover.Dependency) ([][]string, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	// Go note: deps[start:end] is a slice of the same underlying array, not a
	// copy, so chunking a big list this way costs nothing extra.
	ids := make([][]string, 0, len(deps))
	for start := 0; start < len(deps); start += osvBatchLimit {
		end := start + osvBatchLimit
		if end > len(deps) {
			end = len(deps)
		}
		chunk, err := queryOneBatch(deps[start:end])
		if err != nil {
			return nil, err
		}
		if len(chunk) != end-start {
			return nil, fmt.Errorf("OSV.dev querybatch returned %d results for %d queries", len(chunk), end-start)
		}
		ids = append(ids, chunk...)
	}
	return ids, nil
}

// queryOneBatch sends one /querybatch request (at most osvBatchLimit queries).
func queryOneBatch(deps []discover.Dependency) ([][]string, error) {
	reqBody := queryBatchRequest{Queries: make([]batchQuery, len(deps))}
	for i, dep := range deps {
		reqBody.Queries[i] = batchQuery{
			Package: packageRef{Name: dep.Name, Ecosystem: dep.Ecosystem},
			Version: dep.Version,
		}
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(osvAPIBase+"/querybatch", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	// Go note: `defer` schedules a call to run when the surrounding function
	// returns, no matter which return statement triggers it, or even if the
	// function panics. It's the idiomatic way to guarantee cleanup (closing
	// a response body, a file, a lock) without needing a try/finally block --
	// there's no such block in Go, defer covers that need instead.
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV.dev querybatch failed: %s", resp.Status)
	}

	var result queryBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	ids := make([][]string, len(result.Results))
	for i, r := range result.Results {
		for _, v := range r.Vulns {
			ids[i] = append(ids[i], v.ID)
		}
	}
	return ids, nil
}

// VulnDetail is the full advisory record for one OSV.dev id
// (GET /v1/vulns/{id}) -- everything this project needs to build a report
// entry: severity, the affected version ranges (to compute the fix version),
// and the human-readable summary/details/references.
type VulnDetail struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases"`
	Summary  string     `json:"summary"`
	Details  string     `json:"details"`
	Affected []affected `json:"affected"`

	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`

	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

type affected struct {
	Package packageRef     `json:"package"`
	Ranges  []versionRange `json:"ranges"`
}

type versionRange struct {
	Events []event `json:"events"`
}

// event models one entry in an OSV.dev affected-version range. Exactly one of
// these three fields is set per event; an empty string means "not this one"
// (a JSON field that's absent from the response decodes to Go's zero value
// for its type -- "" for a string -- which is how "this event isn't an
// Introduced event" is distinguished from an explicit value).
type event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// GetVulnDetails fetches the full advisory record for one OSV.dev id.
func GetVulnDetails(id string) (*VulnDetail, error) {
	resp, err := http.Get(osvAPIBase + "/vulns/" + id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV.dev vuln lookup failed for %s: %s", id, resp.Status)
	}

	// Go note: returning &detail (a pointer to a local variable) is safe and
	// normal in Go, unlike C/C++ -- Go's garbage collector keeps the value
	// alive for as long as anything still references it, wherever that
	// reference ends up living. There's no equivalent of a "dangling
	// pointer to a stack frame that already returned" to worry about here.
	var detail VulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, err
	}
	return &detail, nil
}
