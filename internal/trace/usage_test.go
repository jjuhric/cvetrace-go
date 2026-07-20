package trace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectCodeReferencesFindsAnNpmRequire(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(`const minimist = require("minimist");`), 0o644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	vulns := []Vulnerability{{Ecosystem: "npm", Name: "minimist"}}
	got, err := DetectCodeReferences(dir, vulns)
	if err != nil {
		t.Fatalf("DetectCodeReferences returned an error: %v", err)
	}
	if got[0].CodeReference != "found" {
		t.Errorf("got codeReference %q, want %q", got[0].CodeReference, "found")
	}
}

func TestDetectCodeReferencesReportsNotFoundWhenNoImportExists(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(`console.log("hello");`), 0o644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	vulns := []Vulnerability{{Ecosystem: "npm", Name: "minimist"}}
	got, err := DetectCodeReferences(dir, vulns)
	if err != nil {
		t.Fatalf("DetectCodeReferences returned an error: %v", err)
	}
	if got[0].CodeReference != "not-found" {
		t.Errorf("got codeReference %q, want %q", got[0].CodeReference, "not-found")
	}
}

func TestDetectCodeReferencesReportsUnknownWhenNoRelevantSourceFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("nothing here is source code"), 0o644); err != nil {
		t.Fatalf("failed to write README.md: %v", err)
	}

	vulns := []Vulnerability{{Ecosystem: "npm", Name: "minimist"}}
	got, err := DetectCodeReferences(dir, vulns)
	if err != nil {
		t.Fatalf("DetectCodeReferences returned an error: %v", err)
	}
	if got[0].CodeReference != "unknown" {
		t.Errorf("got codeReference %q, want %q (no .js/.ts files exist to scan at all)", got[0].CodeReference, "unknown")
	}
}

func TestDetectCodeReferencesMavenChecksGroupIDImport(t *testing.T) {
	dir := t.TempDir()
	javaSrc := "package com.example;\n\nimport org.apache.logging.log4j.core.Appender;\n"
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(javaSrc), 0o644); err != nil {
		t.Fatalf("failed to write App.java: %v", err)
	}

	vulns := []Vulnerability{{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core"}}
	got, err := DetectCodeReferences(dir, vulns)
	if err != nil {
		t.Fatalf("DetectCodeReferences returned an error: %v", err)
	}
	if got[0].CodeReference != "found" {
		t.Errorf("got codeReference %q, want %q (Java import matches the groupId org.apache.logging.log4j)", got[0].CodeReference, "found")
	}
}

func TestDetectCodeReferencesPythonChecksImportStatement(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import yaml\n\nyaml.safe_load(\"...\")\n"), 0o644); err != nil {
		t.Fatalf("failed to write app.py: %v", err)
	}

	vulns := []Vulnerability{{Ecosystem: "PyPI", Name: "yaml"}}
	got, err := DetectCodeReferences(dir, vulns)
	if err != nil {
		t.Fatalf("DetectCodeReferences returned an error: %v", err)
	}
	if got[0].CodeReference != "found" {
		t.Errorf("got codeReference %q, want %q", got[0].CodeReference, "found")
	}
}

func TestDetectCodeReferencesSkipsIgnoredDirectories(t *testing.T) {
	dir := t.TempDir()
	nodeModules := filepath.Join(dir, "node_modules", "minimist")
	if err := os.MkdirAll(nodeModules, 0o755); err != nil {
		t.Fatalf("failed to create node_modules: %v", err)
	}
	// A require("minimist") sitting inside node_modules itself shouldn't
	// count -- it's the dependency's own source, not the project's usage of
	// it, and node_modules can be enormous besides.
	if err := os.WriteFile(filepath.Join(nodeModules, "index.js"), []byte(`module.exports = require("minimist");`), 0o644); err != nil {
		t.Fatalf("failed to write index.js: %v", err)
	}

	vulns := []Vulnerability{{Ecosystem: "npm", Name: "minimist"}}
	got, err := DetectCodeReferences(dir, vulns)
	if err != nil {
		t.Fatalf("DetectCodeReferences returned an error: %v", err)
	}
	if got[0].CodeReference != "unknown" {
		t.Errorf("got codeReference %q, want %q (only source file was inside node_modules, which is skipped)", got[0].CodeReference, "unknown")
	}
}
