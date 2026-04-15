package audit

import (
	"testing"

	"github.com/steadytao/surveyor/internal/core"
)

func TestSelectEndpointsSelectsTLSCandidates(t *testing.T) {
	t.Parallel()

	results := SelectEndpoints([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "0.0.0.0",
			Port:      443,
			Transport: "tcp",
			State:     "listening",
			Hints: []core.DiscoveryHint{
				{
					Protocol:   "tls",
					Confidence: "low",
					Evidence:   []string{"transport=tcp", "port=443"},
				},
			},
		},
	})

	if len(results) != 1 {
		t.Fatalf("len(SelectEndpoints()) = %d, want 1", len(results))
	}

	got := results[0]
	if got.Selection.Status != core.AuditSelectionStatusSelected {
		t.Fatalf("Selection.Status = %q, want %q", got.Selection.Status, core.AuditSelectionStatusSelected)
	}
	if got.Selection.SelectedScanner != "tls" {
		t.Fatalf("Selection.SelectedScanner = %q, want tls", got.Selection.SelectedScanner)
	}
	if got.Selection.Reason != "tls hint on tcp/443" {
		t.Fatalf("Selection.Reason = %q, want tls hint on tcp/443", got.Selection.Reason)
	}
	if got.TLSResult != nil {
		t.Fatalf("TLSResult = %#v, want nil before orchestration", got.TLSResult)
	}
}

func TestSelectEndpointsSelectsResponsiveRemoteTLSCandidates(t *testing.T) {
	t.Parallel()

	results := SelectEndpoints([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "10.0.0.10",
			Port:      443,
			Transport: "tcp",
			State:     "responsive",
			Hints: []core.DiscoveryHint{
				{
					Protocol:   "tls",
					Confidence: "low",
					Evidence:   []string{"transport=tcp", "port=443"},
				},
			},
		},
	})

	if len(results) != 1 {
		t.Fatalf("len(SelectEndpoints()) = %d, want 1", len(results))
	}

	got := results[0]
	if got.Selection.Status != core.AuditSelectionStatusSelected {
		t.Fatalf("Selection.Status = %q, want %q", got.Selection.Status, core.AuditSelectionStatusSelected)
	}
	if got.Selection.SelectedScanner != "tls" {
		t.Fatalf("Selection.SelectedScanner = %q, want tls", got.Selection.SelectedScanner)
	}
	if got.Selection.Reason != "tls hint on tcp/443" {
		t.Fatalf("Selection.Reason = %q, want tls hint on tcp/443", got.Selection.Reason)
	}
}

func TestSelectEndpointsSkipsUnsupportedTransport(t *testing.T) {
	t.Parallel()

	results := SelectEndpoints([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "127.0.0.1",
			Port:      5353,
			Transport: "udp",
			State:     "bound",
		},
	})

	got := results[0]
	if got.Selection.Status != core.AuditSelectionStatusSkipped {
		t.Fatalf("Selection.Status = %q, want %q", got.Selection.Status, core.AuditSelectionStatusSkipped)
	}
	if got.Selection.Reason != "no supported scanner for udp endpoint" {
		t.Fatalf("Selection.Reason = %q, want no supported scanner for udp endpoint", got.Selection.Reason)
	}
}

func TestSelectEndpointsSkipsTCPWithoutHints(t *testing.T) {
	t.Parallel()

	results := SelectEndpoints([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "127.0.0.1",
			Port:      8080,
			Transport: "tcp",
			State:     "listening",
		},
	})

	got := results[0]
	if got.Selection.Status != core.AuditSelectionStatusSkipped {
		t.Fatalf("Selection.Status = %q, want %q", got.Selection.Status, core.AuditSelectionStatusSkipped)
	}
	if got.Selection.Reason != "no supported scanner for endpoint without recognised hints" {
		t.Fatalf("Selection.Reason = %q, want no-hint skip reason", got.Selection.Reason)
	}
}

func TestSelectEndpointsSkipsUnsupportedHints(t *testing.T) {
	t.Parallel()

	results := SelectEndpoints([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "127.0.0.1",
			Port:      22,
			Transport: "tcp",
			State:     "listening",
			Hints: []core.DiscoveryHint{
				{
					Protocol:   "ssh",
					Confidence: "low",
					Evidence:   []string{"transport=tcp", "port=22"},
				},
			},
		},
	})

	got := results[0]
	if got.Selection.Status != core.AuditSelectionStatusSkipped {
		t.Fatalf("Selection.Status = %q, want %q", got.Selection.Status, core.AuditSelectionStatusSkipped)
	}
	if got.Selection.Reason != "no supported scanner for hinted protocols" {
		t.Fatalf("Selection.Reason = %q, want unsupported-hint skip reason", got.Selection.Reason)
	}
}

func TestSelectEndpointsSkipsDiscoveryErrors(t *testing.T) {
	t.Parallel()

	results := SelectEndpoints([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "0.0.0.0",
			Port:      443,
			Transport: "tcp",
			State:     "listening",
			Hints: []core.DiscoveryHint{
				{
					Protocol:   "tls",
					Confidence: "low",
					Evidence:   []string{"transport=tcp", "port=443"},
				},
			},
			Errors: []string{"incomplete discovery result"},
		},
	})

	got := results[0]
	if got.Selection.Status != core.AuditSelectionStatusSkipped {
		t.Fatalf("Selection.Status = %q, want %q", got.Selection.Status, core.AuditSelectionStatusSkipped)
	}
	if got.Selection.Reason != "discovery result contains errors" {
		t.Fatalf("Selection.Reason = %q, want discovery error skip reason", got.Selection.Reason)
	}
}

func TestSelectEndpointsSkipsUnresponsiveRemoteEndpoints(t *testing.T) {
	t.Parallel()

	results := SelectEndpoints([]core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "10.0.0.11",
			Port:      443,
			Transport: "tcp",
			State:     "candidate",
			Errors:    []string{"connection refused"},
		},
	})

	got := results[0]
	if got.Selection.Status != core.AuditSelectionStatusSkipped {
		t.Fatalf("Selection.Status = %q, want %q", got.Selection.Status, core.AuditSelectionStatusSkipped)
	}
	if got.Selection.Reason != "endpoint did not respond during remote discovery" {
		t.Fatalf("Selection.Reason = %q, want remote discovery failure skip reason", got.Selection.Reason)
	}
}

func TestSelectEndpointsClonesDiscoverySlices(t *testing.T) {
	t.Parallel()

	input := []core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "0.0.0.0",
			Port:      443,
			Transport: "tcp",
			State:     "listening",
			Hints: []core.DiscoveryHint{
				{Protocol: "tls", Confidence: "low"},
			},
			Warnings: []string{"warning"},
			Errors:   []string{"error"},
		},
	}

	results := SelectEndpoints(input)
	results[0].DiscoveredEndpoint.Hints[0].Protocol = "mutated"
	results[0].DiscoveredEndpoint.Warnings[0] = "mutated"
	results[0].DiscoveredEndpoint.Errors[0] = "mutated"

	if input[0].Hints[0].Protocol != "tls" {
		t.Fatalf("input hints mutated: %#v", input[0].Hints)
	}
	if input[0].Warnings[0] != "warning" {
		t.Fatalf("input warnings mutated: %#v", input[0].Warnings)
	}
	if input[0].Errors[0] != "error" {
		t.Fatalf("input errors mutated: %#v", input[0].Errors)
	}
}
