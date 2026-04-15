package discovery

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/steadytao/surveyor/internal/core"
)

type connectionLister func(context.Context, string) ([]net.ConnectionStat, error)
type processFactory func(context.Context, int32) (processView, error)

type processView interface {
	NameWithContext(context.Context) (string, error)
	ExeWithContext(context.Context) (string, error)
}

// LocalEnumerator collects local endpoint facts for discovery and local audit input.
type LocalEnumerator struct {
	listConnections connectionLister
	newProcess      processFactory
}

// Enumerate returns stable, deduplicated local endpoints enriched with any
// best-effort process metadata and conservative protocol hints.
func (e LocalEnumerator) Enumerate(ctx context.Context) ([]core.DiscoveredEndpoint, error) {
	listConnections := e.listConnections
	if listConnections == nil {
		listConnections = defaultConnectionLister
	}
	newProcess := e.newProcess
	if newProcess == nil {
		newProcess = defaultProcessFactory
	}

	tcpConnections, err := listConnections(ctx, "tcp")
	if err != nil {
		return nil, err
	}

	udpConnections, err := listConnections(ctx, "udp")
	if err != nil {
		return nil, err
	}

	endpoints := make([]core.DiscoveredEndpoint, 0, len(tcpConnections)+len(udpConnections))
	seen := make(map[string]int, len(tcpConnections)+len(udpConnections))

	appendEndpoint := func(endpoint core.DiscoveredEndpoint) {
		// Some platforms surface the same bound socket more than once, sometimes
		// with different amounts of process metadata. Merge by observed endpoint
		// identity so discovery stays stable and keeps the richest result.
		key := endpoint.Transport + "|" + endpoint.State + "|" + endpoint.Address + "|" + strconv.Itoa(endpoint.Port)
		if index, ok := seen[key]; ok {
			mergeEndpoint(&endpoints[index], endpoint)
			return
		}

		seen[key] = len(endpoints)
		endpoints = append(endpoints, endpoint)
	}

	for _, connection := range tcpConnections {
		if endpoint, ok := tcpEndpoint(ctx, connection, newProcess); ok {
			appendEndpoint(endpoint)
		}
	}

	for _, connection := range udpConnections {
		if endpoint, ok := udpEndpoint(ctx, connection, newProcess); ok {
			appendEndpoint(endpoint)
		}
	}

	sort.Slice(endpoints, func(i, j int) bool {
		left := endpoints[i]
		right := endpoints[j]

		if left.Transport != right.Transport {
			return left.Transport < right.Transport
		}
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}

		return left.State < right.State
	})

	return endpoints, nil
}

func defaultConnectionLister(ctx context.Context, kind string) ([]net.ConnectionStat, error) {
	connections, err := net.ConnectionsWithoutUidsWithContext(ctx, kind)
	if err == nil {
		return connections, nil
	}
	if !strings.Contains(strings.ToLower(err.Error()), "not implemented") {
		return nil, err
	}

	// The reduced-privilege path is not implemented on some platforms. Fall
	// back to the fuller call instead of failing discovery outright.
	return net.ConnectionsWithContext(ctx, kind)
}

func defaultProcessFactory(ctx context.Context, pid int32) (processView, error) {
	return process.NewProcessWithContext(ctx, pid)
}

func tcpEndpoint(ctx context.Context, connection net.ConnectionStat, newProcess processFactory) (core.DiscoveredEndpoint, bool) {
	if connection.Type != uint32(syscall.SOCK_STREAM) {
		return core.DiscoveredEndpoint{}, false
	}
	if connection.Laddr.Port == 0 {
		return core.DiscoveredEndpoint{}, false
	}
	if connection.Status != "LISTEN" {
		return core.DiscoveredEndpoint{}, false
	}

	endpoint := core.DiscoveredEndpoint{
		Address:   connection.Laddr.IP,
		Port:      int(connection.Laddr.Port),
		Transport: "tcp",
		State:     "listening",
	}
	enrichEndpoint(ctx, &endpoint, connection.Pid, newProcess)
	endpoint.Hints = append(endpoint.Hints, inferHints(endpoint)...)

	return endpoint, true
}

func udpEndpoint(ctx context.Context, connection net.ConnectionStat, newProcess processFactory) (core.DiscoveredEndpoint, bool) {
	if connection.Type != uint32(syscall.SOCK_DGRAM) {
		return core.DiscoveredEndpoint{}, false
	}
	if connection.Laddr.Port == 0 {
		return core.DiscoveredEndpoint{}, false
	}

	endpoint := core.DiscoveredEndpoint{
		Address:   connection.Laddr.IP,
		Port:      int(connection.Laddr.Port),
		Transport: "udp",
		State:     "bound",
	}
	enrichEndpoint(ctx, &endpoint, connection.Pid, newProcess)
	endpoint.Hints = append(endpoint.Hints, inferHints(endpoint)...)

	return endpoint, true
}

func enrichEndpoint(ctx context.Context, endpoint *core.DiscoveredEndpoint, pid int32, newProcess processFactory) {
	if endpoint == nil || pid <= 0 {
		return
	}

	endpoint.PID = int(pid)

	// Process metadata is best-effort. Discovery should still report the
	// endpoint even when the current platform or permissions prevent lookup.
	proc, err := newProcess(ctx, pid)
	if err != nil {
		endpoint.Warnings = append(endpoint.Warnings, "process metadata unavailable")
		return
	}

	name, err := proc.NameWithContext(ctx)
	if err == nil && strings.TrimSpace(name) != "" {
		endpoint.ProcessName = name
	}

	executable, err := proc.ExeWithContext(ctx)
	if err == nil && strings.TrimSpace(executable) != "" {
		endpoint.Executable = executable
	}
}

func inferHints(endpoint core.DiscoveredEndpoint) []core.DiscoveryHint {
	if endpoint.Transport != "tcp" {
		return nil
	}

	// Hinting is intentionally conservative and port-based only for now.
	// Verified protocol identification belongs to scanner execution, not discovery.
	switch endpoint.Port {
	case 22:
		return []core.DiscoveryHint{newHint("ssh", endpoint.Transport, endpoint.Port)}
	case 443, 8443:
		return []core.DiscoveryHint{newHint("tls", endpoint.Transport, endpoint.Port)}
	case 3389:
		return []core.DiscoveryHint{newHint("rdp", endpoint.Transport, endpoint.Port)}
	default:
		return nil
	}
}

func newHint(protocol string, transport string, port int) core.DiscoveryHint {
	return core.DiscoveryHint{
		Protocol:   protocol,
		Confidence: "low",
		Evidence: []string{
			"transport=" + transport,
			"port=" + strconv.Itoa(port),
		},
	}
}

func mergeEndpoint(existing *core.DiscoveredEndpoint, incoming core.DiscoveredEndpoint) {
	if existing == nil {
		return
	}

	// Preserve the richest observed metadata without inventing new facts.
	if existing.PID == 0 && incoming.PID != 0 {
		existing.PID = incoming.PID
	}
	if existing.ProcessName == "" && incoming.ProcessName != "" {
		existing.ProcessName = incoming.ProcessName
	}
	if existing.Executable == "" && incoming.Executable != "" {
		existing.Executable = incoming.Executable
	}

	for _, warning := range incoming.Warnings {
		if !slicesContains(existing.Warnings, warning) {
			existing.Warnings = append(existing.Warnings, warning)
		}
	}

	for _, hint := range incoming.Hints {
		if !containsHint(existing.Hints, hint) {
			existing.Hints = append(existing.Hints, hint)
		}
	}
}

func containsHint(hints []core.DiscoveryHint, candidate core.DiscoveryHint) bool {
	for _, hint := range hints {
		if hint.Protocol == candidate.Protocol &&
			hint.Confidence == candidate.Confidence &&
			strings.Join(hint.Evidence, "\x00") == strings.Join(candidate.Evidence, "\x00") {
			return true
		}
	}

	return false
}

func slicesContains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}

	return false
}
