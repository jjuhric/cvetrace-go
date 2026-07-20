package trace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIgnoreFileParsesIDsCommentsAndReasons(t *testing.T) {
	dir := t.TempDir()
	content := "# full-line comment, skipped\n" +
		"\n" + // blank line, skipped
		"CVE-2021-1234\n" +
		"CVE-2021-5678 # reviewed, false positive in our usage\n" +
		"   GHSA-xxxx-xxxx-xxxx   \n" // surrounding whitespace trimmed
	if err := os.WriteFile(filepath.Join(dir, ".cvetraceignore"), []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write .cvetraceignore: %v", err)
	}

	rules, err := LoadIgnoreFile(dir)
	if err != nil {
		t.Fatalf("LoadIgnoreFile returned an error: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("got %d rules, want 3", len(rules))
	}

	byID := make(map[string]IgnoreRule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}

	if r, ok := byID["CVE-2021-1234"]; !ok || r.Reason != "" {
		t.Errorf("got %+v, want CVE-2021-1234 with no reason", r)
	}
	if r, ok := byID["CVE-2021-5678"]; !ok || r.Reason != "reviewed, false positive in our usage" {
		t.Errorf("got %+v, want CVE-2021-5678 with the trailing comment as its reason", r)
	}
	if r, ok := byID["GHSA-xxxx-xxxx-xxxx"]; !ok || r.Source != ".cvetraceignore" {
		t.Errorf("got %+v, want GHSA-xxxx-xxxx-xxxx sourced from .cvetraceignore", r)
	}
}

func TestLoadIgnoreFileReturnsNilWhenNoFileExists(t *testing.T) {
	dir := t.TempDir()
	rules, err := LoadIgnoreFile(dir)
	if err != nil {
		t.Fatalf("LoadIgnoreFile returned an error: %v", err)
	}
	if rules != nil {
		t.Errorf("got %v, want nil (no .cvetraceignore file present)", rules)
	}
}

func TestApplyIgnoreRulesMatchesByIDOrAlias(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "GHSA-aaaa", Aliases: []string{"CVE-2021-1111"}, Name: "pkg-a"},
		{ID: "GHSA-bbbb", Aliases: []string{"CVE-2021-2222"}, Name: "pkg-b"},
		{ID: "GHSA-cccc", Aliases: nil, Name: "pkg-c"},
	}
	fileRules := []IgnoreRule{
		{ID: "CVE-2021-1111", Reason: "accepted risk", Source: ".cvetraceignore"},
	}
	cliIDs := []string{"GHSA-cccc"}

	kept, ignored := ApplyIgnoreRules(vulns, fileRules, cliIDs)

	if len(kept) != 1 || kept[0].Name != "pkg-b" {
		t.Errorf("got kept=%v, want only pkg-b", kept)
	}
	if len(ignored) != 2 {
		t.Fatalf("got %d ignored, want 2", len(ignored))
	}

	byName := make(map[string]IgnoredVulnerability, len(ignored))
	for _, v := range ignored {
		byName[v.Name] = v
	}
	if v := byName["pkg-a"]; v.IgnoredReason != "accepted risk" || v.IgnoredVia != ".cvetraceignore" {
		t.Errorf("pkg-a: got %+v, want matched via .cvetraceignore with a reason", v)
	}
	if v := byName["pkg-c"]; v.IgnoredVia != "--ignore" {
		t.Errorf("pkg-c: got %+v, want matched via --ignore", v)
	}
}

func TestApplyIgnoreRulesKeepsEverythingWhenNoRulesMatch(t *testing.T) {
	vulns := []Vulnerability{{ID: "GHSA-aaaa", Name: "pkg-a"}}
	kept, ignored := ApplyIgnoreRules(vulns, nil, nil)
	if len(kept) != 1 {
		t.Errorf("got %d kept, want 1", len(kept))
	}
	if len(ignored) != 0 {
		t.Errorf("got %d ignored, want 0", len(ignored))
	}
}
