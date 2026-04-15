package discovery

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/shirou/gopsutil/v4/net"

	"github.com/steadytao/surveyor/internal/core"
)

type connectionLister func(context.Context, string) ([]net.ConnectionStat, error)

type LocalEnumerator struct {
	listConnections connectionLister
}

func (e LocalEnumerator) Enumerate(ctx context.Context) ([]core.DiscoveredEndpoint, error) {
	listConnections := e.listConnections
	if listConnections == nil {
		listConnections = defaultConnectionLister
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
	seen := make(map[string]struct{}, len(tcpConnections)+len(udpConnections))

	appendEndpoint := func(endpoint core.DiscoveredEndpoint) {
		key := endpoint.Transport + "|" + endpoint.State + "|" + endpoint.Address + "|" + strconv.Itoa(endpoint.Port)
		if _, ok := seen[key]; ok {
			return
		}

		seen[key] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}

	for _, connection := range tcpConnections {
		if endpoint, ok := tcpEndpoint(connection); ok {
			appendEndpoint(endpoint)
		}
	}

	for _, connection := range udpConnections {
		if endpoint, ok := udpEndpoint(connection); ok {
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

	return net.ConnectionsWithContext(ctx, kind)
}

func tcpEndpoint(connection net.ConnectionStat) (core.DiscoveredEndpoint, bool) {
	if connection.Type != uint32(syscall.SOCK_STREAM) {
		return core.DiscoveredEndpoint{}, false
	}
	if connection.Laddr.Port == 0 {
		return core.DiscoveredEndpoint{}, false
	}
	if connection.Status != "LISTEN" {
		return core.DiscoveredEndpoint{}, false
	}

	return core.DiscoveredEndpoint{
		Address:   connection.Laddr.IP,
		Port:      int(connection.Laddr.Port),
		Transport: "tcp",
		State:     "listening",
	}, true
}

func udpEndpoint(connection net.ConnectionStat) (core.DiscoveredEndpoint, bool) {
	if connection.Type != uint32(syscall.SOCK_DGRAM) {
		return core.DiscoveredEndpoint{}, false
	}
	if connection.Laddr.Port == 0 {
		return core.DiscoveredEndpoint{}, false
	}

	return core.DiscoveredEndpoint{
		Address:   connection.Laddr.IP,
		Port:      int(connection.Laddr.Port),
		Transport: "udp",
		State:     "bound",
	}, true
}
