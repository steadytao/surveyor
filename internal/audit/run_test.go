package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
)

func TestLocalRunnerRunReturnsDiscoveryError(t *testing.T) {
	t.Parallel()

	runner := LocalRunner{
		Discoverer: stubDiscoverer{err: errors.New("discovery failed")},
	}

	_, err := runner.Run(context.Background())
	if err == nil || err.Error() != "discovery failed" {
		t.Fatalf("Run() error = %v, want discovery failed", err)
	}
}

func TestLocalRunnerRunScansSelectedTLSEndpoints(t *testing.T) {
	t.Parallel()

	discovered := []core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "127.0.0.1",
			Port:      443,
			Transport: "tcp",
			State:     "listening",
			Hints: []core.DiscoveryHint{
				{Protocol: "tls", Confidence: "low", Evidence: []string{"transport=tcp", "port=443"}},
			},
		},
		{
			ScopeKind: core.EndpointScopeKindLocal,
			Host:      "127.0.0.1",
			Port:      5353,
			Transport: "udp",
			State:     "bound",
		},
	}

	scanner := &stubTargetScanner{
		result: core.TargetResult{
			Host:           "127.0.0.1",
			Port:           443,
			ScannedAt:      time.Date(2026, time.April, 16, 3, 0, 0, 0, time.UTC),
			Reachable:      true,
			Classification: "modern_tls_classical_identity",
		},
	}

	runner := LocalRunner{
		Discoverer: stubDiscoverer{results: discovered},
		TLSScanner: scanner,
	}

	results, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(Run()) = %d, want 2", len(results))
	}
	if scanner.calls != 1 {
		t.Fatalf("scanner.calls = %d, want 1", scanner.calls)
	}
	if scanner.targets[0].Host != "127.0.0.1" || scanner.targets[0].Port != 443 {
		t.Fatalf("scanner.targets[0] = %#v, want 127.0.0.1:443", scanner.targets[0])
	}

	selected := results[0]
	if selected.Selection.Status != core.AuditSelectionStatusSelected {
		t.Fatalf("selected.Selection.Status = %q, want selected", selected.Selection.Status)
	}
	if selected.TLSResult == nil {
		t.Fatalf("selected.TLSResult = nil, want scan result")
	}
	if selected.TLSResult.Classification != "modern_tls_classical_identity" {
		t.Fatalf("selected.TLSResult.Classification = %q, want modern_tls_classical_identity", selected.TLSResult.Classification)
	}

	skipped := results[1]
	if skipped.Selection.Status != core.AuditSelectionStatusSkipped {
		t.Fatalf("skipped.Selection.Status = %q, want skipped", skipped.Selection.Status)
	}
	if skipped.TLSResult != nil {
		t.Fatalf("skipped.TLSResult = %#v, want nil", skipped.TLSResult)
	}
}

func TestLocalRunnerRunSkipsInvalidSelectedEndpoint(t *testing.T) {
	t.Parallel()

	scanner := &stubTargetScanner{}
	runner := LocalRunner{
		Discoverer: stubDiscoverer{
			results: []core.DiscoveredEndpoint{
				{
					ScopeKind: core.EndpointScopeKindLocal,
					Host:      "",
					Port:      443,
					Transport: "tcp",
					State:     "listening",
					Hints: []core.DiscoveryHint{
						{Protocol: "tls", Confidence: "low"},
					},
				},
			},
		},
		TLSScanner: scanner,
	}

	results, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if scanner.calls != 0 {
		t.Fatalf("scanner.calls = %d, want 0", scanner.calls)
	}
	if len(results) != 1 {
		t.Fatalf("len(Run()) = %d, want 1", len(results))
	}
	if results[0].Selection.Status != core.AuditSelectionStatusSkipped {
		t.Fatalf("Selection.Status = %q, want skipped", results[0].Selection.Status)
	}
	if results[0].TLSResult != nil {
		t.Fatalf("TLSResult = %#v, want nil", results[0].TLSResult)
	}
	if !strings.HasPrefix(results[0].Selection.Reason, "invalid discovered endpoint for tls scan") {
		t.Fatalf("Selection.Reason = %q, want invalid discovered endpoint reason", results[0].Selection.Reason)
	}
}

func TestLocalRunnerRunSkipsUnsupportedSelectedScanner(t *testing.T) {
	t.Parallel()

	scanner := &stubTargetScanner{}
	runner := LocalRunner{
		Discoverer: stubDiscoverer{
			results: []core.DiscoveredEndpoint{
				{
					ScopeKind: core.EndpointScopeKindLocal,
					Host:      "127.0.0.1",
					Port:      22,
					Transport: "tcp",
					State:     "listening",
				},
			},
		},
		TLSScanner: scanner,
		Select: func(endpoints []core.DiscoveredEndpoint) []core.AuditResult {
			return []core.AuditResult{
				{
					DiscoveredEndpoint: endpoints[0],
					Selection: core.AuditSelection{
						Status:          core.AuditSelectionStatusSelected,
						SelectedScanner: "ssh",
						Reason:          "ssh hint on tcp/22",
					},
				},
			}
		},
	}

	results, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if scanner.calls != 0 {
		t.Fatalf("scanner.calls = %d, want 0", scanner.calls)
	}
	if results[0].Selection.Status != core.AuditSelectionStatusSkipped {
		t.Fatalf("Selection.Status = %q, want skipped", results[0].Selection.Status)
	}
	if results[0].Selection.Reason != `selected scanner "ssh" is not implemented` {
		t.Fatalf("Selection.Reason = %q, want unsupported scanner reason", results[0].Selection.Reason)
	}
}

func TestRemoteRunnerRunScansSelectedTLSEndpoints(t *testing.T) {
	t.Parallel()

	discovered := []core.DiscoveredEndpoint{
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "10.0.0.10",
			Port:      443,
			Transport: "tcp",
			State:     "responsive",
			Hints: []core.DiscoveryHint{
				{Protocol: "tls", Confidence: "low", Evidence: []string{"transport=tcp", "port=443"}},
			},
		},
		{
			ScopeKind: core.EndpointScopeKindRemote,
			Host:      "10.0.0.11",
			Port:      443,
			Transport: "tcp",
			State:     "candidate",
			Errors:    []string{"connection refused"},
		},
	}

	scanner := &stubTargetScanner{
		result: core.TargetResult{
			Host:           "10.0.0.10",
			Port:           443,
			ScannedAt:      time.Date(2026, time.April, 16, 4, 0, 0, 0, time.UTC),
			Reachable:      true,
			Classification: "modern_tls_classical_identity",
		},
	}

	runner := RemoteRunner{
		Scope:      config.SubnetScope{},
		Discoverer: stubDiscoverer{results: discovered},
		TLSScanner: scanner,
	}

	results, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(Run()) = %d, want 2", len(results))
	}
	if scanner.calls != 1 {
		t.Fatalf("scanner.calls = %d, want 1", scanner.calls)
	}
	if scanner.targets[0].Host != "10.0.0.10" || scanner.targets[0].Port != 443 {
		t.Fatalf("scanner.targets[0] = %#v, want 10.0.0.10:443", scanner.targets[0])
	}

	selected := results[0]
	if selected.Selection.Status != core.AuditSelectionStatusSelected {
		t.Fatalf("selected.Selection.Status = %q, want selected", selected.Selection.Status)
	}
	if selected.TLSResult == nil {
		t.Fatalf("selected.TLSResult = nil, want scan result")
	}
	if selected.TLSResult.Classification != "modern_tls_classical_identity" {
		t.Fatalf("selected.TLSResult.Classification = %q, want modern_tls_classical_identity", selected.TLSResult.Classification)
	}

	skipped := results[1]
	if skipped.Selection.Status != core.AuditSelectionStatusSkipped {
		t.Fatalf("skipped.Selection.Status = %q, want skipped", skipped.Selection.Status)
	}
	if skipped.Selection.Reason != "endpoint did not respond during remote discovery" {
		t.Fatalf("skipped.Selection.Reason = %q, want remote discovery failure reason", skipped.Selection.Reason)
	}
	if skipped.TLSResult != nil {
		t.Fatalf("skipped.TLSResult = %#v, want nil", skipped.TLSResult)
	}
}

func TestRemoteRunnerRunReturnsDiscoveryError(t *testing.T) {
	t.Parallel()

	runner := RemoteRunner{
		Scope:      config.SubnetScope{},
		Discoverer: stubDiscoverer{err: errors.New("remote discovery failed")},
	}

	_, err := runner.Run(context.Background())
	if err == nil || err.Error() != "remote discovery failed" {
		t.Fatalf("Run() error = %v, want remote discovery failed", err)
	}
}

type stubDiscoverer struct {
	results []core.DiscoveredEndpoint
	err     error
}

func (d stubDiscoverer) Enumerate(context.Context) ([]core.DiscoveredEndpoint, error) {
	if d.err != nil {
		return nil, d.err
	}

	return d.results, nil
}

type stubTargetScanner struct {
	calls   int
	targets []config.Target
	result  core.TargetResult
}

func (s *stubTargetScanner) ScanTarget(_ context.Context, target config.Target) core.TargetResult {
	s.calls += 1
	s.targets = append(s.targets, target)

	result := s.result
	if result.Host == "" {
		result.Host = target.Host
	}
	if result.Port == 0 {
		result.Port = target.Port
	}

	return result
}
