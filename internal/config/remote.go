package config

import (
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RemoteProfile controls the default pace for remote inventory commands.
type RemoteProfile string

const (
	RemoteProfileCautious   RemoteProfile = "cautious"
	RemoteProfileBalanced   RemoteProfile = "balanced"
	RemoteProfileAggressive RemoteProfile = "aggressive"
)

// RemoteScopeInputKind records which declared remote scope shape the command is
// trying to build.
type RemoteScopeInputKind string

const (
	RemoteScopeInputKindCIDR        RemoteScopeInputKind = "cidr"
	RemoteScopeInputKindTargetsFile RemoteScopeInputKind = "targets_file"
)

// RemoteScopeInput is the raw input shape for remote commands.
// Zero-valued pace controls mean "use the selected profile default".
type RemoteScopeInput struct {
	CIDR           string
	Ports          string
	Profile        string
	MaxHosts       int
	MaxConcurrency int
	Timeout        time.Duration
	DryRun         bool
}

// RemoteScope is the validated and normalised scope contract remote commands
// execute against. The current implementation only produces CIDR-backed scope,
// but the type is broader so later file-backed input does not require another
// subnet-shaped rewrite through the codebase.
type RemoteScope struct {
	InputKind      RemoteScopeInputKind
	CIDR           netip.Prefix
	Ports          []int
	Profile        RemoteProfile
	MaxHosts       int
	HostCount      int
	MaxConcurrency int
	Timeout        time.Duration
	DryRun         bool
}

type remoteProfileDefaults struct {
	maxConcurrency int
	timeout        time.Duration
}

var remoteProfileDefaultsByProfile = map[RemoteProfile]remoteProfileDefaults{
	RemoteProfileCautious: {
		maxConcurrency: 8,
		timeout:        3 * time.Second,
	},
	RemoteProfileBalanced: {
		maxConcurrency: 24,
		timeout:        2 * time.Second,
	},
	RemoteProfileAggressive: {
		maxConcurrency: 64,
		timeout:        1 * time.Second,
	},
}

const defaultRemoteMaxHosts = 256

// ParseRemoteScope validates and normalises raw remote input into the current
// remote-scope contract. Today that means explicit CIDR scope and explicit
// ports; later remote input kinds should extend this contract rather than
// replace it.
func ParseRemoteScope(input RemoteScopeInput) (RemoteScope, error) {
	cidrText := strings.TrimSpace(input.CIDR)

	if cidrText == "" {
		return RemoteScope{}, fmt.Errorf("--cidr is required")
	}

	profile, err := parseRemoteProfile(input.Profile)
	if err != nil {
		return RemoteScope{}, err
	}

	prefix, err := netip.ParsePrefix(cidrText)
	if err != nil {
		return RemoteScope{}, fmt.Errorf("invalid --cidr: %w", err)
	}
	prefix = prefix.Masked()

	ports, err := parsePorts(input.Ports)
	if err != nil {
		return RemoteScope{}, err
	}

	maxHosts := input.MaxHosts
	if maxHosts == 0 {
		maxHosts = defaultRemoteMaxHosts
	}
	if maxHosts < 0 {
		return RemoteScope{}, fmt.Errorf("--max-hosts must not be negative")
	}

	hostCount, err := subnetHostCount(prefix)
	if err != nil {
		return RemoteScope{}, err
	}
	if hostCount > maxHosts {
		return RemoteScope{}, fmt.Errorf("--cidr expands to %d hosts, which exceeds --max-hosts=%d", hostCount, maxHosts)
	}

	defaults := remoteProfileDefaultsByProfile[profile]

	maxConcurrency := input.MaxConcurrency
	if maxConcurrency == 0 {
		maxConcurrency = defaults.maxConcurrency
	}
	if maxConcurrency < 0 {
		return RemoteScope{}, fmt.Errorf("--max-concurrency must not be negative")
	}

	timeout := input.Timeout
	if timeout == 0 {
		timeout = defaults.timeout
	}
	if timeout < 0 {
		return RemoteScope{}, fmt.Errorf("--timeout must not be negative")
	}

	return RemoteScope{
		InputKind:      RemoteScopeInputKindCIDR,
		CIDR:           prefix,
		Ports:          ports,
		Profile:        profile,
		MaxHosts:       maxHosts,
		HostCount:      hostCount,
		MaxConcurrency: maxConcurrency,
		Timeout:        timeout,
		DryRun:         input.DryRun,
	}, nil
}

func parseRemoteProfile(raw string) (RemoteProfile, error) {
	profileText := strings.ToLower(strings.TrimSpace(raw))
	if profileText == "" {
		return RemoteProfileCautious, nil
	}

	profile := RemoteProfile(profileText)
	if _, ok := remoteProfileDefaultsByProfile[profile]; !ok {
		return "", fmt.Errorf("invalid --profile %q: must be one of cautious, balanced or aggressive", raw)
	}

	return profile, nil
}

func parsePorts(raw string) ([]int, error) {
	portsText := strings.TrimSpace(raw)
	if portsText == "" {
		return nil, fmt.Errorf("--ports is required")
	}

	parts := strings.Split(portsText, ",")
	seen := make(map[int]struct{}, len(parts))
	ports := make([]int, 0, len(parts))

	for index, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			return nil, fmt.Errorf("--ports[%d] must not be empty", index)
		}

		port, err := strconv.Atoi(entry)
		if err != nil {
			return nil, fmt.Errorf("--ports[%d] must be numeric: %w", index, err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("--ports[%d] must be between 1 and 65535", index)
		}
		if _, ok := seen[port]; ok {
			continue
		}

		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	sort.Ints(ports)
	return ports, nil
}

func subnetHostCount(prefix netip.Prefix) (int, error) {
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits < 0 {
		return 0, fmt.Errorf("invalid --cidr: prefix length exceeds address size")
	}

	// The scope cap counts every address in the declared prefix. Surveyor should
	// fail closed on unexpectedly large declared scope, not try to infer
	// "usable hosts" semantics from address family conventions.
	count := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	if !count.IsInt64() {
		return 0, fmt.Errorf("invalid --cidr: host count is too large to support")
	}

	return int(count.Int64()), nil
}
