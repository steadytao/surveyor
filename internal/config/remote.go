package config

import (
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/steadytao/surveyor/internal/core"
	"github.com/steadytao/surveyor/internal/inventory"
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
	RemoteScopeInputKindCIDR          RemoteScopeInputKind = "cidr"
	RemoteScopeInputKindTargetsFile   RemoteScopeInputKind = "targets_file"
	RemoteScopeInputKindInventoryFile RemoteScopeInputKind = "inventory_file"
)

// RemoteScopeInput is the raw input shape for remote commands.
// Zero-valued pace controls mean "use the selected profile default".
type RemoteScopeInput struct {
	CIDR           string
	TargetsFile    string
	InventoryFile  string
	Ports          string
	Profile        string
	MaxHosts       int
	MaxConcurrency int
	Timeout        time.Duration
	DryRun         bool
}

// RemoteScopeTarget records one executable host:ports target compiled from a
// richer remote input source.
type RemoteScopeTarget struct {
	Host      string
	Ports     []int
	Inventory *core.InventoryAnnotation
}

// RemoteScope is the validated and normalised scope contract remote commands
// execute against. It already supports CIDR-backed and simple file-backed host
// scope so later remote inputs do not require another subnet-shaped rewrite
// through the codebase.
type RemoteScope struct {
	InputKind      RemoteScopeInputKind
	CIDR           netip.Prefix
	TargetsFile    string
	InventoryFile  string
	Hosts          []string
	Ports          []int
	Targets        []RemoteScopeTarget
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
// remote-scope contract. Today that means explicit CIDR scope, a simple
// file-backed host list or a structured inventory manifest; later remote input
// kinds should extend this contract rather than replace it.
func ParseRemoteScope(input RemoteScopeInput) (RemoteScope, error) {
	cidrText := strings.TrimSpace(input.CIDR)
	targetsFileText := strings.TrimSpace(input.TargetsFile)
	inventoryFileText := strings.TrimSpace(input.InventoryFile)

	scopeInputCount := 0
	if cidrText != "" {
		scopeInputCount++
	}
	if targetsFileText != "" {
		scopeInputCount++
	}
	if inventoryFileText != "" {
		scopeInputCount++
	}
	if scopeInputCount > 1 {
		return RemoteScope{}, fmt.Errorf("use exactly one of --cidr, --targets-file or --inventory-file")
	}
	if scopeInputCount == 0 {
		return RemoteScope{}, fmt.Errorf("one of --cidr, --targets-file or --inventory-file is required")
	}

	profile, err := parseRemoteProfile(input.Profile)
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

	if inventoryFileText != "" {
		document, err := inventory.Load(inventoryFileText)
		if err != nil {
			return RemoteScope{}, fmt.Errorf("load --inventory-file %q: %w", inventoryFileText, err)
		}
		if len(document.Entries) > maxHosts {
			return RemoteScope{}, fmt.Errorf("--inventory-file contains %d hosts, which exceeds --max-hosts=%d", len(document.Entries), maxHosts)
		}

		overridePorts, err := parseOptionalPorts(input.Ports)
		if err != nil {
			return RemoteScope{}, err
		}

		targets, err := compileInventoryTargets(document.Entries, overridePorts)
		if err != nil {
			return RemoteScope{}, fmt.Errorf("--inventory-file %q: %w", inventoryFileText, err)
		}

		return RemoteScope{
			InputKind:      RemoteScopeInputKindInventoryFile,
			InventoryFile:  inventoryFileText,
			Ports:          overridePorts,
			Targets:        targets,
			Profile:        profile,
			MaxHosts:       maxHosts,
			HostCount:      len(targets),
			MaxConcurrency: maxConcurrency,
			Timeout:        timeout,
			DryRun:         input.DryRun,
		}, nil
	}

	ports, err := requirePorts(input.Ports)
	if err != nil {
		return RemoteScope{}, err
	}

	if targetsFileText != "" {
		hosts, err := parseRemoteTargetsFile(targetsFileText)
		if err != nil {
			return RemoteScope{}, err
		}
		if len(hosts) == 0 {
			return RemoteScope{}, fmt.Errorf("--targets-file %q does not contain any hosts", targetsFileText)
		}
		if len(hosts) > maxHosts {
			return RemoteScope{}, fmt.Errorf("--targets-file contains %d hosts, which exceeds --max-hosts=%d", len(hosts), maxHosts)
		}

		return RemoteScope{
			InputKind:      RemoteScopeInputKindTargetsFile,
			TargetsFile:    targetsFileText,
			Hosts:          hosts,
			Ports:          ports,
			Profile:        profile,
			MaxHosts:       maxHosts,
			HostCount:      len(hosts),
			MaxConcurrency: maxConcurrency,
			Timeout:        timeout,
			DryRun:         input.DryRun,
		}, nil
	}

	prefix, err := netip.ParsePrefix(cidrText)
	if err != nil {
		return RemoteScope{}, fmt.Errorf("invalid --cidr: %w", err)
	}
	prefix = prefix.Masked()

	hostCount, err := subnetHostCount(prefix)
	if err != nil {
		return RemoteScope{}, err
	}
	if hostCount > maxHosts {
		return RemoteScope{}, fmt.Errorf("--cidr expands to %d hosts, which exceeds --max-hosts=%d", hostCount, maxHosts)
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

func requirePorts(raw string) ([]int, error) {
	ports, err := parseOptionalPorts(raw)
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("--ports is required")
	}

	return ports, nil
}

func parseOptionalPorts(raw string) ([]int, error) {
	portsText := strings.TrimSpace(raw)
	if portsText == "" {
		return nil, nil
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

func compileInventoryTargets(entries []inventory.Entry, overridePorts []int) ([]RemoteScopeTarget, error) {
	targets := make([]RemoteScopeTarget, 0, len(entries))
	for _, entry := range entries {
		ports := append([]int(nil), overridePorts...)
		if len(ports) == 0 {
			ports = append([]int(nil), entry.Ports...)
		}
		if len(ports) == 0 {
			return nil, fmt.Errorf("host %q does not declare any ports and --ports was not provided", entry.Host)
		}

		targets = append(targets, RemoteScopeTarget{
			Host:      entry.Host,
			Ports:     ports,
			Inventory: entry.Annotation(),
		})
	}

	return targets, nil
}

func parseRemoteTargetsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --targets-file %q: %w", path, err)
	}

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	hosts := make([]string, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		host, err := validateRemoteHost(line)
		if err != nil {
			return nil, fmt.Errorf("--targets-file %q: %w", path, err)
		}

		key := remoteHostKey(host)
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}
		hosts = append(hosts, host)
	}

	return hosts, nil
}

func validateRemoteHost(raw string) (string, error) {
	target, err := ValidateTarget(Target{
		Host: raw,
		Port: 1,
	})
	if err != nil {
		return "", err
	}

	return target.Host, nil
}

func remoteHostKey(host string) string {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String()
	}

	return strings.ToLower(host)
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
