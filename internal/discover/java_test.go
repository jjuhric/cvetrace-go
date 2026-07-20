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
	if log4j.DependencyScope != "direct" {
		t.Errorf("got dependencyScope %q, want %q (pom.xml isn't resolved transitively)", log4j.DependencyScope, "direct")
	}
	if log4j.UsageContext != "production" {
		t.Errorf("got usageContext %q, want %q (no <scope> tag defaults to compile/production)", log4j.UsageContext, "production")
	}
}

func TestFromPomXMLTagsTestScopeAsDevelopment(t *testing.T) {
	pom := `<project>
  <dependencies>
    <dependency>
      <groupId>org.junit</groupId>
      <artifactId>junit</artifactId>
      <version>5.9.0</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`

	deps, err := fromPomXML([]byte(pom), "pom.xml")
	if err != nil {
		t.Fatalf("fromPomXML returned an error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1", len(deps))
	}
	if deps[0].UsageContext != "development" {
		t.Errorf("got usageContext %q, want %q (<scope>test</scope> should map to development)", deps[0].UsageContext, "development")
	}
	if deps[0].DependencyScope != "direct" {
		t.Errorf("got dependencyScope %q, want %q", deps[0].DependencyScope, "direct")
	}
}
