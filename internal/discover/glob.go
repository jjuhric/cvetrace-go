package discover

import (
	"regexp"
	"strings"
)

// specialChars lists the regex metacharacters GlobToRegexp must escape when
// they appear literally in a glob pattern (e.g. a package scope's "@" is
// fine as-is, but a literal "." in a directory name must not be allowed to
// mean "any character" once translated to a regex).
const specialChars = `.+^${}()|[]\`

// GlobToRegexp compiles a minimal, dependency-free glob pattern (used for
// --exclude) into a regexp matched against a directory's path relative to
// the scanned target (forward-slash separated, regardless of OS). Supports
// "*" (any characters except "/"), "?" (single character except "/"), and
// "**" (any characters, including "/"). A pattern ending in "/**" also
// matches the prefix itself (e.g. "test/**" matches both "test" and
// "test/fixtures/foo"), since "skip this directory tree" is the common
// intent.
//
// Go note: this operates on a []rune, not the string directly -- indexing a
// Go string with [i] gives a single *byte*, which would silently mis-slice
// any multi-byte UTF-8 character (unlikely in a glob pattern, but cheap to
// get right). Converting to []rune once up front means every index refers
// to one whole character, the same way JS string indexing already does.
func GlobToRegexp(pattern string) *regexp.Regexp {
	normalized := strings.ReplaceAll(pattern, `\`, "/")
	trailingRecursive := strings.HasSuffix(normalized, "/**")
	if trailingRecursive {
		normalized = normalized[:len(normalized)-len("/**")]
	}

	runes := []rune(normalized)
	var out strings.Builder
	out.WriteString("^")

	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == '*' && i+1 < len(runes) && runes[i+1] == '*':
			out.WriteString(".*")
			i++
			if i+1 < len(runes) && runes[i+1] == '/' {
				i++
			}
		case c == '*':
			out.WriteString("[^/]*")
		case c == '?':
			out.WriteString("[^/]")
		case strings.ContainsRune(specialChars, c):
			out.WriteRune('\\')
			out.WriteRune(c)
		default:
			out.WriteRune(c)
		}
	}

	if trailingRecursive {
		out.WriteString("(?:/.*)?$")
	} else {
		out.WriteString("$")
	}

	return regexp.MustCompile(out.String())
}

// NewExcludeMatcher builds a relativePath -> bool matcher from a list of
// glob patterns, for both Walk (skipping manifest directories) and
// usage-detection's own directory walk (skipping source directories).
func NewExcludeMatcher(patterns []string) func(relPath string) bool {
	regexes := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		regexes[i] = GlobToRegexp(p)
	}
	return func(relPath string) bool {
		normalized := strings.ReplaceAll(relPath, `\`, "/")
		for _, re := range regexes {
			if re.MatchString(normalized) {
				return true
			}
		}
		return false
	}
}
