package discovery

import (
	"context"
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
					},
				}, nil
			case "udp":
				return []gopsnet.ConnectionStat{
					{
						Type:  2,
						Laddr: gopsnet.Addr{IP: "127.0.0.1", Port: 5353},
					},
				}, nil
			default:
				t.Fatalf("unexpected kind %q", kind)
				return nil, nil
			}
		},
	}

	got, err := enumerator.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate() error = %v", err)
	}

	want := []core.DiscoveredEndpoint{
		{Address: "0.0.0.0", Port: 443, Transport: "tcp", State: "listening"},
		{Address: "127.0.0.1", Port: 8443, Transport: "tcp", State: "listening"},
		{Address: "127.0.0.1", Port: 5353, Transport: "udp", State: "bound"},
	}

	if len(got) != len(want) {
		t.Fatalf("len(Enumerate()) = %d, want %d; got %#v", len(got), len(want), got)
	}

	for index := range want {
		if got[index].Address != want[index].Address ||
			got[index].Port != want[index].Port ||
			got[index].Transport != want[index].Transport ||
			got[index].State != want[index].State {
			t.Fatalf("Enumerate()[%d] = %#v, want %#v", index, got[index], want[index])
		}
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
