package trace

import (
	"strings"
	"testing"
)

func TestGenerateOverrideSnippetReturnsNilForDirectDependencies(t *testing.T) {
	v := Vulnerability{Ecosystem: "npm", Name: "minimist", DependencyScope: "direct", FixedVersion: "0.2.4"}
	if got := generateOverrideSnippet(v); got != nil {
		t.Errorf("got %+v, want nil (direct dependencies have no parent to force past)", got)
	}
}

func TestGenerateOverrideSnippetReturnsNilWithoutAKnownTargetVersion(t *testing.T) {
	v := Vulnerability{Ecosystem: "npm", Name: "vulnerable-pkg", DependencyScope: "transitive", FixedVersion: ""}
	if got := generateOverrideSnippet(v); got != nil {
		t.Errorf("got %+v, want nil (no fixedVersion or recommendedVersion to target)", got)
	}
}

func TestGenerateOverrideSnippetNpmUsesRecommendedVersionOverFixedVersion(t *testing.T) {
	v := Vulnerability{
		Ecosystem:          "npm",
		Name:               "vulnerable-pkg",
		DependencyScope:    "transitive",
		FixedVersion:       "1.2.4",
		RecommendedVersion: "1.5.0", // clears more than just this one CVE
	}

	got := generateOverrideSnippet(v)
	if got == nil {
		t.Fatal("got nil, want a snippet")
	}
	if got.File != "package.json" {
		t.Errorf("got file %q, want %q", got.File, "package.json")
	}
	if !strings.Contains(got.Snippet, `"vulnerable-pkg": "1.5.0"`) {
		t.Errorf("got snippet %q, want it to force version 1.5.0 (the recommendedVersion), not 1.2.4", got.Snippet)
	}
	if !strings.Contains(got.Snippet, `"overrides"`) {
		t.Errorf("got snippet %q, want an npm \"overrides\" block", got.Snippet)
	}
}

func TestGenerateOverrideSnippetGradleForcesResolutionStrategy(t *testing.T) {
	v := Vulnerability{
		Ecosystem:       "Maven",
		Name:            "org.example:lib",
		ManifestPath:    "sub/build.gradle",
		DependencyScope: "transitive",
		FixedVersion:    "2.0.0",
	}

	got := generateOverrideSnippet(v)
	if got == nil {
		t.Fatal("got nil, want a snippet")
	}
	if got.File != "build.gradle" {
		t.Errorf("got file %q, want %q (basename of the manifest path)", got.File, "build.gradle")
	}
	if !strings.Contains(got.Snippet, "resolutionStrategy.force 'org.example:lib:2.0.0'") {
		t.Errorf("got snippet %q, want a resolutionStrategy.force line", got.Snippet)
	}
}

func TestGenerateOverrideSnippetGradleKtsManifestUsesItsOwnBasename(t *testing.T) {
	v := Vulnerability{
		Ecosystem:       "Maven",
		Name:            "org.example:lib",
		ManifestPath:    "build.gradle.kts",
		DependencyScope: "transitive",
		FixedVersion:    "2.0.0",
	}

	got := generateOverrideSnippet(v)
	if got == nil || got.File != "build.gradle.kts" {
		t.Errorf("got %+v, want file %q", got, "build.gradle.kts")
	}
}

func TestGenerateOverrideSnippetMavenProducesDependencyManagementBlock(t *testing.T) {
	// Unreachable in practice today (discoverJava never tags a finding
	// "transitive"), but the function itself should still behave correctly
	// in isolation -- see its doc comment.
	v := Vulnerability{
		Ecosystem:       "Maven",
		Name:            "org.example:lib",
		ManifestPath:    "pom.xml",
		DependencyScope: "transitive",
		FixedVersion:    "2.0.0",
	}

	got := generateOverrideSnippet(v)
	if got == nil {
		t.Fatal("got nil, want a snippet")
	}
	if got.File != "pom.xml" {
		t.Errorf("got file %q, want %q", got.File, "pom.xml")
	}
	if !strings.Contains(got.Snippet, "<dependencyManagement>") || !strings.Contains(got.Snippet, "<version>2.0.0</version>") {
		t.Errorf("got snippet %q, want a <dependencyManagement> block forcing version 2.0.0", got.Snippet)
	}
}

func TestApplyOverrideSnippetsDoesNotMutateItsInput(t *testing.T) {
	original := []Vulnerability{
		{Ecosystem: "npm", Name: "vulnerable-pkg", DependencyScope: "transitive", FixedVersion: "1.2.4"},
	}

	got := ApplyOverrideSnippets(original)
	if original[0].OverrideSnippet != nil {
		t.Error("ApplyOverrideSnippets should not mutate its input slice")
	}
	if got[0].OverrideSnippet == nil {
		t.Error("expected the returned slice to have OverrideSnippet set")
	}
}
