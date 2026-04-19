package discovery

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	gopsnet "github.com/shirou/gopsutil/v4/net"

	"github.com/steadytao/surveyor/internal/core"
)

func TestLocalEnumeratorEnumerateFiltersAndSortsEndpoints(t *testing.T) {
	t.Parallel()

	enumerator := LocalEnumerator{
		listConnections: func(_ context.Context, kind string) ([]gopsnet.ConnectionStat, error) {
			switch kind {
			case "tcp":
				return []gopsnet.ConnectionStat{
					{
						Type:   1,
						Status: "ESTABLISHED",
						Laddr:  gopsnet.Addr{IP: "127.0.0.1", Port: 443},
					},
					{
						Type:   1,
						Status: "LISTEN",
						Laddr:  gopsnet.Addr{IP: "127.0.0.1", Port: 8443},
						Pid:    1001,
					},
					{
						Type:   1,
						Status: "LISTEN",
						Laddr:  gopsnet.Addr{IP: "127.0.0.1", Port: 8443},
					},
					{
						Type:   1,
						Status: "LISTEN",
						Laddr:  gopsnet.Addr{IP: "0.0.0.0", Port: 443},
						Pid:    2002,
					},
				}, nil
			case "udp":
				return []gopsnet.ConnectionStat{
					{
						Type:  2,
						Laddr: gopsnet.Addr{IP: "127.0.0.1", Port: 5353},
						Pid:   3003,
					},
				}, nil
			default:
				t.Fatalf("unexpected kind %q", kind)
				return nil, nil
			}
		},
		newProcess: func(_ context.Context, pid int32) (processView, error) {
			switch pid {
			case 1001:
				return stubProcess{name: "local-service", exe: "C:\\SurveyorTest\\local-service.exe"}, nil
			case 2002:
				return nil, errors.New("process lookup failed")
			case 3003:
				return stubProcess{name: "mdnsd"}, nil
			default:
				t.Fatalf("unexpected pid %d", pid)
				return nil, nil
			}
		},
	}

	got, err := enumerator.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate() error = %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("len(Enumerate()) = %d, want 3; got %#v", len(got), got)
	}

	assertLocalEndpoint(t, got[0], "0.0.0.0", 443, "tcp", "listening")
	assertLocalWarning(t, got[0], "process metadata unavailable")
	assertSingleHint(t, got[0], "tls", "low")
	if got[0].PID != 2002 {
		t.Fatalf("got[0].PID = %d, want 2002", got[0].PID)
	}

	assertLocalEndpoint(t, got[1], "127.0.0.1", 8443, "tcp", "listening")
	assertLocalProcess(t, got[1], 1001, "local-service", "C:\\SurveyorTest\\local-service.exe")
	assertSingleHint(t, got[1], "tls", "low")

	assertLocalEndpoint(t, got[2], "127.0.0.1", 5353, "udp", "bound")
	assertLocalProcess(t, got[2], 3003, "mdnsd", "")
	assertNoHints(t, got[2])
}

func TestLocalEnumeratorEnumerateFindsLiveTCPAndUDPListeners(t *testing.T) {
	t.Parallel()

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(tcp) error = %v", err)
	}
	defer tcpListener.Close()

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(udp) error = %v", err)
	}
	defer udpConn.Close()

	tcpHost, tcpPort := splitHostPort(t, tcpListener.Addr().String())
	udpHost, udpPort := splitHostPort(t, udpConn.LocalAddr().String())

	enumerator := LocalEnumerator{}

	var endpoints []core.DiscoveredEndpoint
	deadline := time.Now().Add(3 * time.Second)
	for {
		endpoints, err = enumerator.Enumerate(context.Background())
		if err != nil {
			t.Fatalf("Enumerate() error = %v", err)
		}
		if hasEndpoint(endpoints, "tcp", "listening", tcpHost, tcpPort) && hasEndpoint(endpoints, "udp", "bound", udpHost, udpPort) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Enumerate() did not observe expected endpoints; got %#v", endpoints)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func splitHostPort(t *testing.T, address string) (string, int) {
	t.Helper()

	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", address, err)
	}

	port, err := net.LookupPort("", portText)
	if err != nil {
		t.Fatalf("LookupPort(%q) error = %v", portText, err)
	}

	return host, port
}

func hasEndpoint(endpoints []core.DiscoveredEndpoint, transport string, state string, address string, port int) bool {
	for _, endpoint := range endpoints {
		if endpoint.Transport == transport && endpoint.State == state && endpoint.Host == address && endpoint.Port == port {
			return true
		}
	}

	return false
}

func assertLocalEndpoint(t *testing.T, endpoint core.DiscoveredEndpoint, host string, port int, transport string, state string) {
	t.Helper()

	if endpoint.ScopeKind != core.EndpointScopeKindLocal || endpoint.Host != host || endpoint.Port != port || endpoint.Transport != transport || endpoint.State != state {
		t.Fatalf("endpoint = %#v, want local %s endpoint on %s:%d in state %q", endpoint, transport, host, port, state)
	}
}

func assertLocalProcess(t *testing.T, endpoint core.DiscoveredEndpoint, pid int, name string, executable string) {
	t.Helper()

	if endpoint.PID != pid || endpoint.ProcessName != name || endpoint.Executable != executable {
		t.Fatalf("endpoint enrichment = %#v, want pid=%d name=%q executable=%q", endpoint, pid, name, executable)
	}
}

func assertLocalWarning(t *testing.T, endpoint core.DiscoveredEndpoint, warning string) {
	t.Helper()

	if len(endpoint.Warnings) != 1 || endpoint.Warnings[0] != warning {
		t.Fatalf("endpoint.Warnings = %#v, want [%q]", endpoint.Warnings, warning)
	}
}

func assertSingleHint(t *testing.T, endpoint core.DiscoveredEndpoint, protocol string, confidence string) {
	t.Helper()

	if len(endpoint.Hints) != 1 || endpoint.Hints[0].Protocol != protocol || endpoint.Hints[0].Confidence != confidence {
		t.Fatalf("endpoint.Hints = %#v, want one %s hint with confidence %q", endpoint.Hints, protocol, confidence)
	}
}

func assertNoHints(t *testing.T, endpoint core.DiscoveredEndpoint) {
	t.Helper()

	if len(endpoint.Hints) != 0 {
		t.Fatalf("endpoint.Hints = %#v, want no hints", endpoint.Hints)
	}
}

type stubProcess struct {
	name string
	exe  string
}

func (p stubProcess) NameWithContext(context.Context) (string, error) {
	if p.name == "" {
		return "", errors.New("name unavailable")
	}

	return p.name, nil
}

func (p stubProcess) ExeWithContext(context.Context) (string, error) {
	if p.exe == "" {
		return "", errors.New("exe unavailable")
	}

	return p.exe, nil
}
