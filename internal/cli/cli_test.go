package cli

import (
	"reflect"
	"testing"
)

// TestReorderFlagsFirst is a regression test for a real bug caught while
// building this: "cvetrace scan <path> --json" was silently ignoring --json,
// because Go's flag package stops looking for flags at the first positional
// argument, and <path> came first. See the comment on reorderFlagsFirst.
func TestReorderFlagsFirst(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "flag after the positional argument",
			in:   []string{"test/my-project", "--json"},
			want: []string{"--json", "test/my-project"},
		},
		{
			name: "flag already first, unchanged",
			in:   []string{"--json", "test/my-project"},
			want: []string{"--json", "test/my-project"},
		},
		{
			name: "no flags at all",
			in:   []string{"test/my-project"},
			want: []string{"test/my-project"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := reorderFlagsFirst(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
