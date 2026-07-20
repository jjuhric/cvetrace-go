package discover

import "testing"

func TestGlobToRegexp(t *testing.T) {
	cases := []struct {
		name, pattern, path string
		want                bool
	}{
		{"exact match", "test", "test", true},
		{"exact no match", "test", "testing", false},
		{"single star doesn't cross a slash", "test/*", "test/foo", true},
		{"single star doesn't cross a slash, negative", "test/*", "test/foo/bar", false},
		{"double star crosses slashes", "test/**", "test/foo/bar", true},
		{"trailing /** also matches the prefix itself", "test/**", "test", true},
		{"question mark matches one character", "te?t", "test", true},
		{"question mark doesn't match two characters", "te?t", "teXXt", false},
		{"literal dot isn't a wildcard", "a.b", "aXb", false},
		{"literal dot matches itself", "a.b", "a.b", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GlobToRegexp(c.pattern).MatchString(c.path)
			if got != c.want {
				t.Errorf("GlobToRegexp(%q).MatchString(%q) = %v, want %v", c.pattern, c.path, got, c.want)
			}
		})
	}
}

func TestNewExcludeMatcherMatchesAnyPattern(t *testing.T) {
	isExcluded := NewExcludeMatcher([]string{"test/**", "legacy/**"})

	if !isExcluded("test/fixtures/foo") {
		t.Error("expected test/fixtures/foo to be excluded (matches test/**)")
	}
	if !isExcluded("legacy/old.js") {
		t.Error("expected legacy/old.js to be excluded (matches legacy/**)")
	}
	if isExcluded("src/index.js") {
		t.Error("expected src/index.js not to be excluded (matches neither pattern)")
	}
}

func TestNewExcludeMatcherNormalizesBackslashes(t *testing.T) {
	isExcluded := NewExcludeMatcher([]string{"test/**"})
	if !isExcluded(`test\fixtures\foo`) {
		t.Error("expected a Windows-style backslash path to still match a forward-slash glob pattern")
	}
}
