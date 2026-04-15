package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAuditResultJSONShape(t *testing.T) {
	t.Parallel()

	result := AuditResult{
		DiscoveredEndpoint: DiscoveredEndpoint{
			Address:     "0.0.0.0",
			Port:        443,
			Transport:   "tcp",
			State:       "listening",
			PID:         1234,
			ProcessName: "local-service",
			Hints: []DiscoveryHint{
				{
					Protocol:   "tls",
					Confidence: "low",
					Evidence:   []string{"transport=tcp", "port=443"},
				},
			},
		},
		Selection: AuditSelection{
			Status:          AuditSelectionStatusSelected,
			SelectedScanner: "tls",
			Reason:          "tls hint on tcp/443",
		},
		TLSResult: &TargetResult{
			Host:           "127.0.0.1",
			Port:           443,
			ScannedAt:      time.Date(2026, time.April, 16, 2, 0, 0, 0, time.UTC),
			Reachable:      true,
			Classification: "modern_tls_classical_identity",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)

	wantSubstrings := []string{
		`"discovered_endpoint":{`,
		`"address":"0.0.0.0"`,
		`"selection":{"status":"selected","selected_scanner":"tls","reason":"tls hint on tcp/443"}`,
		`"tls_result":{"host":"127.0.0.1","port":443`,
		`"classification":"modern_tls_classical_identity"`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestAuditReportJSONShape(t *testing.T) {
	t.Parallel()

	report := AuditReport{
		GeneratedAt: time.Date(2026, time.April, 16, 2, 30, 0, 0, time.UTC),
		Results: []AuditResult{
			{
				DiscoveredEndpoint: DiscoveredEndpoint{
					Address:   "127.0.0.1",
					Port:      5353,
					Transport: "udp",
					State:     "bound",
				},
				Selection: AuditSelection{
					Status: AuditSelectionStatusSkipped,
					Reason: "no supported scanner for udp endpoint",
				},
			},
		},
		Summary: AuditSummary{
			TotalEndpoints:   1,
			SkippedEndpoints: 1,
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)

	wantSubstrings := []string{
		`"generated_at":"2026-04-16T02:30:00Z"`,
		`"results":[`,
		`"selection":{"status":"skipped","reason":"no supported scanner for udp endpoint"}`,
		`"summary":{"total_endpoints":1,"tls_candidates":0,"scanned_endpoints":0,"skipped_endpoints":1}`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}
