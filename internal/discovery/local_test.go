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
				return stubProcess{name: "caddy", exe: "C:\\caddy.exe"}, nil
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

	tcpTLS := got[0]
	if tcpTLS.Address != "0.0.0.0" || tcpTLS.Port != 443 || tcpTLS.Transport != "tcp" || tcpTLS.State != "listening" {
		t.Fatalf("got[0] = %#v, want tcp listener on 0.0.0.0:443", tcpTLS)
	}
	if tcpTLS.PID != 2002 {
		t.Fatalf("got[0].PID = %d, want 2002", tcpTLS.PID)
	}
	if len(tcpTLS.Warnings) != 1 || tcpTLS.Warnings[0] != "process metadata unavailable" {
		t.Fatalf("got[0].Warnings = %#v, want process metadata warning", tcpTLS.Warnings)
	}
	if len(tcpTLS.Hints) != 1 || tcpTLS.Hints[0].Protocol != "tls" || tcpTLS.Hints[0].Confidence != "low" {
		t.Fatalf("got[0].Hints = %#v, want low-confidence tls hint", tcpTLS.Hints)
	}

	tcpCaddy := got[1]
	if tcpCaddy.Address != "127.0.0.1" || tcpCaddy.Port != 8443 || tcpCaddy.Transport != "tcp" || tcpCaddy.State != "listening" {
		t.Fatalf("got[1] = %#v, want tcp listener on 127.0.0.1:8443", tcpCaddy)
	}
	if tcpCaddy.PID != 1001 || tcpCaddy.ProcessName != "caddy" || tcpCaddy.Executable != "C:\\caddy.exe" {
		t.Fatalf("got[1] enrichment = %#v, want pid/name/executable", tcpCaddy)
	}
	if len(tcpCaddy.Hints) != 1 || tcpCaddy.Hints[0].Protocol != "tls" {
		t.Fatalf("got[1].Hints = %#v, want tls hint", tcpCaddy.Hints)
	}

	udpMDNS := got[2]
	if udpMDNS.Address != "127.0.0.1" || udpMDNS.Port != 5353 || udpMDNS.Transport != "udp" || udpMDNS.State != "bound" {
		t.Fatalf("got[2] = %#v, want udp bound endpoint on 127.0.0.1:5353", udpMDNS)
	}
	if udpMDNS.PID != 3003 || udpMDNS.ProcessName != "mdnsd" {
		t.Fatalf("got[2] enrichment = %#v, want udp pid/name", udpMDNS)
	}
	if len(udpMDNS.Hints) != 0 {
		t.Fatalf("got[2].Hints = %#v, want no hints", udpMDNS.Hints)
	}
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
		if endpoint.Transport == transport && endpoint.State == state && endpoint.Address == address && endpoint.Port == port {
			return true
		}
	}

	return false
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
