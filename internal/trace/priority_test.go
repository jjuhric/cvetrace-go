package trace

import "testing"

func TestComputePriority(t *testing.T) {
	cases := []struct {
		name      string
		v         Vulnerability
		wantScore float64
		wantLabel string
	}{
		{
			name: "critical, production, found in code -> P1",
			v: Vulnerability{
				Severity: "CRITICAL", UsageContext: "production", CodeReference: "found", UpdateImpact: "unknown",
			},
			wantScore: 4.0,
			wantLabel: "P1",
		},
		{
			name: "critical, dev-only, no code reference -> P4 despite CRITICAL severity",
			v: Vulnerability{
				Severity: "CRITICAL", UsageContext: "development", CodeReference: "not-found", UpdateImpact: "unknown",
			},
			// 4 * 0.3 * 0.4 = 0.48
			wantScore: 0.48,
			wantLabel: "P4",
		},
		{
			name: "moderate, production, found, patch bump gets a small easy-win bonus",
			v: Vulnerability{
				Severity: "MODERATE", UsageContext: "production", CodeReference: "found", UpdateImpact: "patch",
			},
			// 2 * 1.0 * 1.0 + 0.3 = 2.3
			wantScore: 2.3,
			wantLabel: "P2",
		},
		{
			name: "unknown severity/context/usage all fall back to their unknown multipliers",
			v: Vulnerability{
				Severity: "SOMETHING-UNRECOGNIZED", UsageContext: "unknown", CodeReference: "unknown", UpdateImpact: "unknown",
			},
			wantScore: 0,
			wantLabel: "P4",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotScore, gotLabel := ComputePriority(c.v)
			if gotScore != c.wantScore {
				t.Errorf("got priorityScore %v, want %v", gotScore, c.wantScore)
			}
			if gotLabel != c.wantLabel {
				t.Errorf("got priorityLabel %q, want %q", gotLabel, c.wantLabel)
			}
		})
	}
}

func TestApplyPrioritySortsByScoreDescending(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "low", Severity: "LOW", UsageContext: "development", CodeReference: "not-found"},
		{ID: "high", Severity: "CRITICAL", UsageContext: "production", CodeReference: "found"},
		{ID: "mid", Severity: "MODERATE", UsageContext: "production", CodeReference: "found"},
	}

	got := ApplyPriority(vulns)
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3", len(got))
	}
	if got[0].ID != "high" || got[1].ID != "mid" || got[2].ID != "low" {
		t.Errorf("got order %v, want [high, mid, low] (sorted by priorityScore descending)",
			[]string{got[0].ID, got[1].ID, got[2].ID})
	}
	for _, v := range got {
		if v.PriorityLabel == "" {
			t.Errorf("expected every record to have a non-empty priorityLabel, got %+v", v)
		}
	}
}
