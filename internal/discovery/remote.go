package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
)

type endpointProber func(context.Context, string, int, time.Duration) error

type remoteProbeTask struct {
	index int
	host  string
	port  int
}

type indexedEndpoint struct {
	index    int
	endpoint core.DiscoveredEndpoint
}

// RemoteEnumerator walks explicitly declared remote scope and records one
// observed result per attempted host:port pair. It attaches only conservative
// port-based hints for responsive endpoints and does not run verified scanners.
type RemoteEnumerator struct {
	Scope         config.RemoteScope
	probeEndpoint endpointProber
}

// Enumerate probes the declared remote TCP scope using bounded concurrency and
// returns stable endpoint observations for both responsive and non-responsive
// attempts within that scope.
func (e RemoteEnumerator) Enumerate(ctx context.Context) ([]core.DiscoveredEndpoint, error) {
	scope := e.Scope
	if len(scope.Ports) == 0 {
		return nil, fmt.Errorf("remote scope ports must not be empty")
	}
	if scope.MaxConcurrency <= 0 {
		return nil, fmt.Errorf("remote scope max concurrency must be greater than 0")
	}
	if scope.Timeout <= 0 {
		return nil, fmt.Errorf("remote scope timeout must be greater than 0")
	}

	hosts, err := resolveRemoteHosts(scope)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, nil
	}

	probeEndpoint := e.probeEndpoint
	if probeEndpoint == nil {
		probeEndpoint = defaultEndpointProber
	}

	taskCount := len(hosts) * len(scope.Ports)
	workerCount := scope.MaxConcurrency
	if workerCount > taskCount {
		workerCount = taskCount
	}

	tasks := make(chan remoteProbeTask)
	results := make(chan indexedEndpoint, workerCount)

	var workerGroup sync.WaitGroup
	for index := 0; index < workerCount; index++ {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()

			for task := range tasks {
				results <- probeRemoteEndpoint(ctx, probeEndpoint, task, scope.Timeout)
			}
		}()
	}

	collected := make([]indexedEndpoint, 0, taskCount)
	var collectGroup sync.WaitGroup
	collectGroup.Add(1)
	go func() {
		defer collectGroup.Done()

		for result := range results {
			collected = append(collected, result)
		}
	}()

	sendErr := enqueueRemoteTasks(ctx, tasks, hosts, scope.Ports)
	close(tasks)
	workerGroup.Wait()
	close(results)
	collectGroup.Wait()

	if sendErr != nil {
		return nil, sendErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Slice(collected, func(i, j int) bool {
		return collected[i].index < collected[j].index
	})

	endpoints := make([]core.DiscoveredEndpoint, 0, len(collected))
	for _, result := range collected {
		endpoints = append(endpoints, result.endpoint)
	}

	return endpoints, nil
}

func resolveRemoteHosts(scope config.RemoteScope) ([]string, error) {
	switch scope.InputKind {
	case config.RemoteScopeInputKindCIDR:
		if !scope.CIDR.IsValid() {
			return nil, fmt.Errorf("remote scope CIDR must be valid")
		}

		return expandRemoteHosts(scope.CIDR)
	case config.RemoteScopeInputKindTargetsFile:
		if len(scope.Hosts) == 0 {
			return nil, fmt.Errorf("remote scope hosts must not be empty")
		}

		return append([]string(nil), scope.Hosts...), nil
	default:
		return nil, fmt.Errorf("unsupported remote scope input kind %q", scope.InputKind)
	}
}

func defaultEndpointProber(ctx context.Context, host string, port int, timeout time.Duration) error {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}

	return conn.Close()
}

func enqueueRemoteTasks(ctx context.Context, tasks chan<- remoteProbeTask, hosts []string, ports []int) error {
	taskIndex := 0

	for _, host := range hosts {
		for _, port := range ports {
			task := remoteProbeTask{
				index: taskIndex,
				host:  host,
				port:  port,
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case tasks <- task:
				taskIndex++
			}
		}
	}

	return nil
}

func probeRemoteEndpoint(ctx context.Context, probe endpointProber, task remoteProbeTask, timeout time.Duration) indexedEndpoint {
	endpoint := core.DiscoveredEndpoint{
		ScopeKind: core.EndpointScopeKindRemote,
		Host:      task.host,
		Port:      task.port,
		Transport: "tcp",
		State:     "candidate",
	}

	// Remote discovery records reachability facts first. A successful TCP
	// connect is enough to mark an endpoint responsive, and only then can later
	// hinting attach conservative port-based suggestions.
	if err := probe(ctx, task.host, task.port, timeout); err == nil {
		endpoint.State = "responsive"
		endpoint.Hints = append(endpoint.Hints, inferHints(endpoint)...)
	} else {
		endpoint.Errors = []string{normaliseProbeError(err)}
	}

	return indexedEndpoint{
		index:    task.index,
		endpoint: endpoint,
	}
}

func normaliseProbeError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "probe cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "probe timed out"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "probe timed out"
	}

	return strings.TrimSpace(err.Error())
}

func expandRemoteHosts(prefix netip.Prefix) ([]string, error) {
	if !prefix.IsValid() {
		return nil, fmt.Errorf("remote scope CIDR must be valid")
	}

	hosts := make([]string, 0)
	for address := prefix.Masked().Addr(); ; {
		if !address.IsValid() || !prefix.Contains(address) {
			break
		}

		hosts = append(hosts, address.String())

		next := address.Next()
		if !next.IsValid() {
			break
		}

		address = next
	}

	return hosts, nil
}
