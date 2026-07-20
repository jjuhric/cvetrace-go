package discover

import (
	"path/filepath"
	"testing"
)

func TestDiscoverJavaResolvesPropertyReference(t *testing.T) {
	fixture := filepath.Join("..", "..", "test", "fixtures", "java-fixture-project")

	deps, err := discoverJava(fixture)
	if err != nil {
		t.Fatalf("discoverJava returned an error: %v", err)
	}

	var log4j *Dependency
	for i := range deps {
		if deps[i].Name == "org.apache.logging.log4j:log4j-core" {
			log4j = &deps[i]
			break
		}
	}

	if log4j == nil {
		t.Fatal("expected log4j-core to be discovered")
	}
	if log4j.Ecosystem != "Maven" {
		t.Errorf("got ecosystem %q, want %q", log4j.Ecosystem, "Maven")
	}
	if log4j.Version != "2.14.1" {
		t.Errorf("got version %q, want %q (should be resolved from the ${log4j.version} property)", log4j.Version, "2.14.1")
	}
}
