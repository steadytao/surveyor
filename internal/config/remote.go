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

// RemoteProfile controls the default pace for future remote inventory commands.
type RemoteProfile string

const (
	RemoteProfileCautious   RemoteProfile = "cautious"
	RemoteProfileBalanced   RemoteProfile = "balanced"
	RemoteProfileAggressive RemoteProfile = "aggressive"
)

// SubnetScopeInput is the raw input shape for future remote subnet commands.
// Zero-valued pace controls mean "use the selected profile default".
type SubnetScopeInput struct {
	CIDR           string
	TargetsFile    string
	Ports          string
	Profile        string
	MaxHosts       int
	MaxConcurrency int
	Timeout        time.Duration
	DryRun         bool
}

// SubnetScope is the validated and normalised scope for future remote subnet commands.
type SubnetScope struct {
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

// ParseSubnetScope validates and normalises raw remote subnet input into the
// contract future remote commands will execute against.
func ParseSubnetScope(input SubnetScopeInput) (SubnetScope, error) {
	cidrText := strings.TrimSpace(input.CIDR)
	targetsFile := strings.TrimSpace(input.TargetsFile)

	switch {
	case cidrText != "" && targetsFile != "":
		return SubnetScope{}, fmt.Errorf("use either --cidr or --targets-file, not both")
	case cidrText == "" && targetsFile == "":
		return SubnetScope{}, fmt.Errorf("one of --cidr or --targets-file is required")
	case targetsFile != "":
		return SubnetScope{}, fmt.Errorf("--targets-file is not supported yet")
	}

	profile, err := parseRemoteProfile(input.Profile)
	if err != nil {
		return SubnetScope{}, err
	}

	prefix, err := netip.ParsePrefix(cidrText)
	if err != nil {
		return SubnetScope{}, fmt.Errorf("invalid --cidr: %w", err)
	}
	prefix = prefix.Masked()

	ports, err := parsePorts(input.Ports)
	if err != nil {
		return SubnetScope{}, err
	}

	maxHosts := input.MaxHosts
	if maxHosts == 0 {
		maxHosts = defaultRemoteMaxHosts
	}
	if maxHosts < 0 {
		return SubnetScope{}, fmt.Errorf("--max-hosts must not be negative")
	}

	hostCount, err := subnetHostCount(prefix)
	if err != nil {
		return SubnetScope{}, err
	}
	if hostCount > maxHosts {
		return SubnetScope{}, fmt.Errorf("--cidr expands to %d hosts, which exceeds --max-hosts=%d", hostCount, maxHosts)
	}

	defaults := remoteProfileDefaultsByProfile[profile]

	maxConcurrency := input.MaxConcurrency
	if maxConcurrency == 0 {
		maxConcurrency = defaults.maxConcurrency
	}
	if maxConcurrency < 0 {
		return SubnetScope{}, fmt.Errorf("--max-concurrency must not be negative")
	}

	timeout := input.Timeout
	if timeout == 0 {
		timeout = defaults.timeout
	}
	if timeout < 0 {
		return SubnetScope{}, fmt.Errorf("--timeout must not be negative")
	}

	return SubnetScope{
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
