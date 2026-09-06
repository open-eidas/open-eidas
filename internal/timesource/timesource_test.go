package timesource

import (
	"testing"
	"time"
)

func testOptions() Options {
	return Options{
		Policy:     PolicyEnforce,
		MinSources: 2,
		MaxOffset:  500 * time.Millisecond,
		MaxAge:     time.Hour,
	}
}

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Minute)

	cases := []struct {
		name      string
		samples   []Sample
		traceable bool
	}{
		{
			name: "deux sources concordantes",
			samples: []Sample{
				{Server: "a", Offset: 12 * time.Millisecond, At: fresh},
				{Server: "b", Offset: -8 * time.Millisecond, At: fresh},
			},
			traceable: true,
		},
		{
			name: "quorum non atteint",
			samples: []Sample{
				{Server: "a", Offset: 5 * time.Millisecond, At: fresh},
				{Server: "b", At: fresh, Err: "i/o timeout"},
			},
		},
		{
			name: "dérive supérieure au seuil",
			samples: []Sample{
				{Server: "a", Offset: 900 * time.Millisecond, At: fresh},
				{Server: "b", Offset: 880 * time.Millisecond, At: fresh},
			},
		},
		{
			name: "sources en désaccord",
			samples: []Sample{
				{Server: "a", Offset: 300 * time.Millisecond, At: fresh},
				{Server: "b", Offset: -300 * time.Millisecond, At: fresh},
			},
		},
		{
			name: "mesure périmée",
			samples: []Sample{
				{Server: "a", Offset: time.Millisecond, At: now.Add(-3 * time.Hour)},
				{Server: "b", Offset: time.Millisecond, At: now.Add(-3 * time.Hour)},
			},
		},
		{
			name:    "aucune source jointe",
			samples: []Sample{{Server: "a", At: fresh, Err: "unreachable"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status := evaluate(tc.samples, testOptions(), now)
			if status.Traceable != tc.traceable {
				t.Fatalf("traçabilité attendue %v, obtenue %v (raison: %s)",
					tc.traceable, status.Traceable, status.Reason)
			}
			if !status.Traceable && status.Reason == "" {
				t.Error("un refus doit être motivé")
			}
		})
	}
}

func TestNowRefusesUntraceableTimeInEnforceMode(t *testing.T) {
	m, err := New(Options{Servers: []string{"a", "b"}, Policy: PolicyEnforce, MinSources: 2})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.Now(); err == nil {
		t.Fatal("sans mesure, la politique enforce doit refuser de fournir l'heure")
	}
}

func TestNowAllowsUntraceableTimeInMonitorMode(t *testing.T) {
	m, err := New(Options{Servers: []string{"a"}, Policy: PolicyMonitor, MinSources: 1})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.Now(); err != nil {
		t.Fatalf("la politique monitor ne doit pas bloquer l'horodatage: %v", err)
	}
}

func TestNewRejectsQuorumLargerThanSourceCount(t *testing.T) {
	if _, err := New(Options{Servers: []string{"a"}, MinSources: 2}); err == nil {
		t.Fatal("exiger plus de sources qu'il n'en est configuré doit être refusé")
	}
}
