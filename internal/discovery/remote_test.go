// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
)

func TestRemoteEnumeratorEnumerateRecordsResponsiveAndFailedAttempts(t *testing.T) {
	t.Parallel()

	enumerator := remoteEnumeratorForCIDR(t, "10.0.0.0/30", "8443,443", 3, 2*time.Second, func(host string, port int) error {
		switch host + ":" + itoa(port) {
		case "10.0.0.1:443", "10.0.0.2:8443":
			return nil
		case "10.0.0.0:443":
			return timeoutProbeError{}
		default:
			return errors.New("connection refused")
		}
	})

	got, err := enumerator.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate() error = %v", err)
	}

	if gotLen, wantLen := len(got), 8; gotLen != wantLen {
		t.Fatalf("len(Enumerate()) = %d, want %d", gotLen, wantLen)
	}

	wantOrder := []struct {
		host  string
		port  int
		state string
		err   string
		hint  string
	}{
		{host: "10.0.0.0", port: 443, state: "candidate", err: "probe timed out"},
		{host: "10.0.0.0", port: 8443, state: "candidate", err: "connection refused"},
		{host: "10.0.0.1", port: 443, state: "responsive", hint: "tls"},
		{host: "10.0.0.1", port: 8443, state: "candidate", err: "connection refused"},
		{host: "10.0.0.2", port: 443, state: "candidate", err: "connection refused"},
		{host: "10.0.0.2", port: 8443, state: "responsive", hint: "tls"},
		{host: "10.0.0.3", port: 443, state: "candidate", err: "connection refused"},
		{host: "10.0.0.3", port: 8443, state: "candidate", err: "connection refused"},
	}

	for index, want := range wantOrder {
		assertRemoteEndpoint(t, got[index], want.host, want.port, want.state)
		assertRemoteProbeOutcome(t, got[index], want.err, want.hint)
	}
}

func TestRemoteEnumeratorEnumerateBoundsConcurrency(t *testing.T) {
	t.Parallel()

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		CIDR:           "10.0.0.0/30",
		Ports:          "443",
		MaxConcurrency: 2,
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	var mu sync.Mutex
	inFlight := 0
	maxInFlight := 0
	timeouts := make([]time.Duration, 0, 4)

	enumerator := RemoteEnumerator{
		Scope: scope,
		probeEndpoint: func(_ context.Context, _ string, _ int, timeout time.Duration) error {
			mu.Lock()
			inFlight++
			if inFlight > maxInFlight {
				maxInFlight = inFlight
			}
			timeouts = append(timeouts, timeout)
			mu.Unlock()

			time.Sleep(25 * time.Millisecond)

			mu.Lock()
			inFlight--
			mu.Unlock()
			return errors.New("connection refused")
		},
	}

	got, err := enumerator.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate() error = %v", err)
	}

	if len(got) != 4 {
		t.Fatalf("len(Enumerate()) = %d, want 4", len(got))
	}

	mu.Lock()
	defer mu.Unlock()

	if maxInFlight > 2 {
		t.Fatalf("max concurrent probes = %d, want <= 2", maxInFlight)
	}
	if maxInFlight != 2 {
		t.Fatalf("max concurrent probes = %d, want 2 to prove the cap is actually used", maxInFlight)
	}

	for index, timeout := range timeouts {
		if timeout != time.Second {
			t.Fatalf("timeouts[%d] = %s, want 1s", index, timeout)
		}
	}
}

func TestRemoteEnumeratorEnumerateTargetsFilePreservesDeclaredHostOrder(t *testing.T) {
	t.Parallel()

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		TargetsFile:    writeTargetsFile(t, "example.com\n10.0.0.10\n"),
		Ports:          "8443,443",
		MaxConcurrency: 2,
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	enumerator := RemoteEnumerator{
		Scope: scope,
		probeEndpoint: func(_ context.Context, host string, port int, timeout time.Duration) error {
			if timeout != time.Second {
				t.Fatalf("timeout = %s, want 1s", timeout)
			}
			if host == "example.com" && port == 443 {
				return nil
			}

			return errors.New("connection refused")
		},
	}

	got, err := enumerator.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate() error = %v", err)
	}

	wantOrder := []struct {
		host  string
		port  int
		state string
	}{
		{host: "example.com", port: 443, state: "responsive"},
		{host: "example.com", port: 8443, state: "candidate"},
		{host: "10.0.0.10", port: 443, state: "candidate"},
		{host: "10.0.0.10", port: 8443, state: "candidate"},
	}

	if len(got) != len(wantOrder) {
		t.Fatalf("len(Enumerate()) = %d, want %d", len(got), len(wantOrder))
	}

	for index, want := range wantOrder {
		if got[index].Host != want.host || got[index].Port != want.port || got[index].State != want.state {
			t.Fatalf("got[%d] = %#v, want host=%q port=%d state=%q", index, got[index], want.host, want.port, want.state)
		}
	}
}

func TestRemoteEnumeratorEnumerateInventoryFilePreservesPortsOrderAndAnnotations(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "inventory.yaml")
	if err := os.WriteFile(inventoryFile, []byte(strings.Join([]string{
		"version: 1",
		"entries:",
		"  - host: EXAMPLE.COM",
		"    ports: [443, 8443]",
		"    owner: Platform",
		"    tags: [external, critical]",
		"  - address: 10.0.0.10",
		"    ports: [9443]",
		"    owner: Core",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		InventoryFile:  inventoryFile,
		MaxConcurrency: 2,
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	enumerator := RemoteEnumerator{
		Scope: scope,
		probeEndpoint: func(_ context.Context, host string, port int, timeout time.Duration) error {
			if timeout != time.Second {
				t.Fatalf("timeout = %s, want 1s", timeout)
			}
			if host == "example.com" && port == 443 {
				return nil
			}

			return errors.New("connection refused")
		},
	}

	got, err := enumerator.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate() error = %v", err)
	}

	wantOrder := []struct {
		host  string
		port  int
		state string
		owner string
	}{{"example.com", 443, "responsive", "Platform"}, {"example.com", 8443, "candidate", "Platform"}, {"10.0.0.10", 9443, "candidate", "Core"}}

	if len(got) != len(wantOrder) {
		t.Fatalf("len(Enumerate()) = %d, want %d", len(got), len(wantOrder))
	}

	for index, want := range wantOrder {
		assertRemoteEndpoint(t, got[index], want.host, want.port, want.state)
		assertInventoryOwner(t, got[index], want.owner)
	}

	if got, want := got[0].Inventory.Ports, []int{443, 8443}; !equalInts(got, want) {
		t.Fatalf("got[0].Inventory.Ports = %v, want %v", got, want)
	}
	if got, want := got[2].Inventory.Ports, []int{9443}; !equalInts(got, want) {
		t.Fatalf("got[2].Inventory.Ports = %v, want %v", got, want)
	}

	got[0].Inventory.Tags[0] = "mutated"
	if got[1].Inventory.Tags[0] != "critical" {
		t.Fatalf("got[1].Inventory.Tags[0] = %q, want independent annotation clone", got[1].Inventory.Tags[0])
	}
}

func remoteEnumeratorForCIDR(
	t *testing.T,
	cidr string,
	ports string,
	maxConcurrency int,
	timeout time.Duration,
	probe func(host string, port int) error,
) RemoteEnumerator {
	t.Helper()

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		CIDR:           cidr,
		Ports:          ports,
		MaxConcurrency: maxConcurrency,
		Timeout:        timeout,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	return RemoteEnumerator{
		Scope: scope,
		probeEndpoint: func(_ context.Context, host string, port int, gotTimeout time.Duration) error {
			if gotTimeout != timeout {
				t.Fatalf("timeout = %s, want %s", gotTimeout, timeout)
			}
			return probe(host, port)
		},
	}
}

func assertRemoteEndpoint(t *testing.T, endpoint core.DiscoveredEndpoint, host string, port int, state string) {
	t.Helper()

	if endpoint.ScopeKind != core.EndpointScopeKindRemote {
		t.Fatalf("endpoint.ScopeKind = %q, want remote", endpoint.ScopeKind)
	}
	if endpoint.Host != host || endpoint.Port != port {
		t.Fatalf("endpoint address = %s:%d, want %s:%d", endpoint.Host, endpoint.Port, host, port)
	}
	if endpoint.Transport != "tcp" {
		t.Fatalf("endpoint.Transport = %q, want tcp", endpoint.Transport)
	}
	if endpoint.State != state {
		t.Fatalf("endpoint.State = %q, want %q", endpoint.State, state)
	}
}

func assertRemoteProbeOutcome(t *testing.T, endpoint core.DiscoveredEndpoint, errText string, hint string) {
	t.Helper()

	if errText == "" {
		if len(endpoint.Errors) != 0 {
			t.Fatalf("endpoint.Errors = %#v, want none", endpoint.Errors)
		}
		if len(endpoint.Hints) != 1 || endpoint.Hints[0].Protocol != hint || endpoint.Hints[0].Confidence != "low" {
			t.Fatalf("endpoint.Hints = %#v, want low-confidence %q hint", endpoint.Hints, hint)
		}
		return
	}

	if len(endpoint.Errors) != 1 || endpoint.Errors[0] != errText {
		t.Fatalf("endpoint.Errors = %#v, want [%q]", endpoint.Errors, errText)
	}
	if len(endpoint.Hints) != 0 {
		t.Fatalf("endpoint.Hints = %#v, want no hints for failed probe", endpoint.Hints)
	}
}

func assertInventoryOwner(t *testing.T, endpoint core.DiscoveredEndpoint, owner string) {
	t.Helper()

	if endpoint.Inventory == nil {
		t.Fatal("endpoint.Inventory = nil, want non-nil")
	}
	if endpoint.Inventory.Owner != owner {
		t.Fatalf("endpoint.Inventory.Owner = %q, want %q", endpoint.Inventory.Owner, owner)
	}
}

func TestRemoteEnumeratorEnumerateInventoryFileUsesOverridePortsAndPreservesImportedPorts(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	inventoryFile := filepath.Join(tempDir, "inventory.yaml")
	if err := os.WriteFile(inventoryFile, []byte(strings.Join([]string{
		"version: 1",
		"entries:",
		"  - host: example.com",
		"    ports: [443, 8443]",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		InventoryFile:  inventoryFile,
		Ports:          "10443",
		MaxConcurrency: 1,
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	enumerator := RemoteEnumerator{
		Scope: scope,
		probeEndpoint: func(_ context.Context, host string, port int, _ time.Duration) error {
			if host != "example.com" || port != 10443 {
				t.Fatalf("probe target = %s:%d, want example.com:10443", host, port)
			}
			return nil
		},
	}

	got, err := enumerator.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate() error = %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len(Enumerate()) = %d, want 1", len(got))
	}
	if got[0].Port != 10443 {
		t.Fatalf("got[0].Port = %d, want 10443", got[0].Port)
	}
	if got[0].Inventory == nil {
		t.Fatal("got[0].Inventory = nil, want non-nil")
	}
	if got, want := got[0].Inventory.Ports, []int{443, 8443}; !equalInts(got, want) {
		t.Fatalf("got[0].Inventory.Ports = %v, want imported ports preserved", got)
	}
}

func TestRemoteEnumeratorEnumerateReturnsContextCancellation(t *testing.T) {
	t.Parallel()

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		CIDR:           "10.0.0.0/30",
		Ports:          "443",
		MaxConcurrency: 2,
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	enumerator := RemoteEnumerator{
		Scope: scope,
		probeEndpoint: func(ctx context.Context, _ string, _ int, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
				return nil
			}
		},
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err = enumerator.Enumerate(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Enumerate() error = %v, want context.Canceled", err)
	}
}

func TestExpandRemoteHostsReturnsCanonicalAddressOrder(t *testing.T) {
	t.Parallel()

	scope, err := config.ParseRemoteScope(config.RemoteScopeInput{
		CIDR:  "10.0.0.9/30",
		Ports: "443",
	})
	if err != nil {
		t.Fatalf("ParseRemoteScope() error = %v", err)
	}

	got, err := expandRemoteHosts(scope.CIDR)
	if err != nil {
		t.Fatalf("expandRemoteHosts() error = %v", err)
	}

	want := []string{"10.0.0.8", "10.0.0.9", "10.0.0.10", "10.0.0.11"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expandRemoteHosts() = %v, want %v", got, want)
	}
}

func writeTargetsFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}

func equalInts(left []int, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}

	return true
}

func itoa(value int) string {
	return strconv.Itoa(value)
}

type timeoutProbeError struct{}

func (timeoutProbeError) Error() string   { return "i/o timeout" }
func (timeoutProbeError) Timeout() bool   { return true }
func (timeoutProbeError) Temporary() bool { return false }
