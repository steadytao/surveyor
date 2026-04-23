// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/steadytao/surveyor/internal/debugassert"
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
// Zero-valued concurrency and timeout use the selected profile defaults; host
// and attempt caps use fixed command defaults.
type RemoteScopeInput struct {
	CIDR           string
	TargetsFile    string
	InventoryFile  string
	Adapter        string
	AdapterBinary  string
	Ports          string
	Profile        string
	MaxHosts       int
	MaxAttempts    int
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
	Adapter        core.InventoryAdapter
	Hosts          []string
	Ports          []int
	Targets        []RemoteScopeTarget
	Profile        RemoteProfile
	MaxHosts       int
	HostCount      int
	MaxAttempts    int
	AttemptCount   int
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
const defaultRemoteMaxAttempts = 2048

// ParseRemoteScope validates and normalises raw remote input into the current
// remote-scope contract. Today that means explicit CIDR scope, a simple
// file-backed host list or a structured inventory manifest; later remote input
// kinds should extend this contract rather than replace it.
func ParseRemoteScope(input RemoteScopeInput) (RemoteScope, error) {
	cidrText, targetsFileText, inventoryFileText, adapterText, adapterBinaryText, err := normalizeRemoteScopeInput(input)
	if err != nil {
		return RemoteScope{}, err
	}

	profile, err := parseRemoteProfile(input.Profile)
	if err != nil {
		return RemoteScope{}, err
	}

	maxHosts, maxAttempts, maxConcurrency, timeout, err := resolveRemoteExecutionLimits(input, profile)
	if err != nil {
		return RemoteScope{}, err
	}

	if inventoryFileText != "" {
		scope, err := parseInventoryRemoteScope(
			inventoryFileText,
			adapterText,
			adapterBinaryText,
			input.Ports,
			profile,
			maxHosts,
			maxAttempts,
			maxConcurrency,
			timeout,
			input.DryRun,
		)
		if err == nil {
			assertValidRemoteScope(scope)
		}
		return scope, err
	}

	ports, err := requirePorts(input.Ports)
	if err != nil {
		return RemoteScope{}, err
	}

	if targetsFileText != "" {
		scope, err := parseTargetsFileRemoteScope(
			targetsFileText,
			ports,
			profile,
			maxHosts,
			maxAttempts,
			maxConcurrency,
			timeout,
			input.DryRun,
		)
		if err == nil {
			assertValidRemoteScope(scope)
		}
		return scope, err
	}

	scope, err := parseCIDRRemoteScope(
		cidrText,
		ports,
		profile,
		maxHosts,
		maxAttempts,
		maxConcurrency,
		timeout,
		input.DryRun,
	)
	if err == nil {
		assertValidRemoteScope(scope)
	}
	return scope, err
}

func normalizeRemoteScopeInput(input RemoteScopeInput) (string, string, string, string, string, error) {
	cidrText := strings.TrimSpace(input.CIDR)
	targetsFileText := strings.TrimSpace(input.TargetsFile)
	inventoryFileText := strings.TrimSpace(input.InventoryFile)
	adapterText := strings.TrimSpace(input.Adapter)
	adapterBinaryText := strings.TrimSpace(input.AdapterBinary)

	if err := validateRemoteScopeInputSelection(cidrText, targetsFileText, inventoryFileText); err != nil {
		return "", "", "", "", "", err
	}
	if inventoryFileText == "" && adapterText != "" {
		return "", "", "", "", "", fmt.Errorf("--adapter requires --inventory-file")
	}
	if inventoryFileText == "" && adapterBinaryText != "" {
		return "", "", "", "", "", fmt.Errorf("--adapter-bin requires --inventory-file")
	}

	return cidrText, targetsFileText, inventoryFileText, adapterText, adapterBinaryText, nil
}

func validateRemoteScopeInputSelection(cidrText string, targetsFileText string, inventoryFileText string) error {
	scopeInputs := []string{cidrText, targetsFileText, inventoryFileText}
	count := 0
	for _, input := range scopeInputs {
		if input != "" {
			count++
		}
	}

	switch count {
	case 0:
		return fmt.Errorf("one of --cidr, --targets-file or --inventory-file is required")
	case 1:
		return nil
	default:
		return fmt.Errorf("use exactly one of --cidr, --targets-file or --inventory-file")
	}
}

func resolveRemoteExecutionLimits(input RemoteScopeInput, profile RemoteProfile) (int, int, int, time.Duration, error) {
	maxHosts, err := remoteCountOrDefault("--max-hosts", input.MaxHosts, defaultRemoteMaxHosts)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	maxAttempts, err := remoteCountOrDefault("--max-attempts", input.MaxAttempts, defaultRemoteMaxAttempts)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	defaults := remoteProfileDefaultsByProfile[profile]
	maxConcurrency, err := remoteCountOrDefault("--max-concurrency", input.MaxConcurrency, defaults.maxConcurrency)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	timeout, err := remoteDurationOrDefault("--timeout", input.Timeout, defaults.timeout)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	return maxHosts, maxAttempts, maxConcurrency, timeout, nil
}

func remoteCountOrDefault(flagName string, value int, fallback int) (int, error) {
	switch {
	case value < 0:
		return 0, fmt.Errorf("%s must not be negative", flagName)
	case value == 0:
		return fallback, nil
	default:
		return value, nil
	}
}

func remoteDurationOrDefault(flagName string, value time.Duration, fallback time.Duration) (time.Duration, error) {
	switch {
	case value < 0:
		return 0, fmt.Errorf("%s must not be negative", flagName)
	case value == 0:
		return fallback, nil
	default:
		return value, nil
	}
}

func parseInventoryRemoteScope(
	inventoryFileText string,
	adapterText string,
	adapterBinaryText string,
	portsText string,
	profile RemoteProfile,
	maxHosts int,
	maxAttempts int,
	maxConcurrency int,
	timeout time.Duration,
	dryRun bool,
) (RemoteScope, error) {
	adapter, err := resolveInventoryAdapter(inventoryFileText, adapterText)
	if err != nil {
		return RemoteScope{}, err
	}
	if adapterBinaryText != "" && adapter == "" {
		return RemoteScope{}, fmt.Errorf("--adapter-bin requires --adapter or an auto-detected adapter-backed inventory file")
	}

	document, err := loadInventoryDocument(inventoryFileText, adapter, adapterBinaryText)
	if err != nil {
		return RemoteScope{}, err
	}
	if len(document.Entries) > maxHosts {
		return RemoteScope{}, fmt.Errorf("--inventory-file contains %d hosts, which exceeds --max-hosts=%d", len(document.Entries), maxHosts)
	}

	overridePorts, err := parseOptionalPorts(portsText)
	if err != nil {
		return RemoteScope{}, err
	}

	targets, err := compileInventoryTargets(document.Entries, overridePorts)
	if err != nil {
		return RemoteScope{}, fmt.Errorf("--inventory-file %q: %w", inventoryFileText, err)
	}
	attemptCount, err := inventoryAttemptCount(targets)
	if err != nil {
		return RemoteScope{}, fmt.Errorf("--inventory-file %q: %w", inventoryFileText, err)
	}
	if attemptCount > maxAttempts {
		return RemoteScope{}, fmt.Errorf("--inventory-file expands to %d host:port attempts, which exceeds --max-attempts=%d", attemptCount, maxAttempts)
	}

	return RemoteScope{
		InputKind:      RemoteScopeInputKindInventoryFile,
		InventoryFile:  inventoryFileText,
		Adapter:        adapter,
		Ports:          overridePorts,
		Targets:        targets,
		Profile:        profile,
		MaxHosts:       maxHosts,
		HostCount:      len(targets),
		MaxAttempts:    maxAttempts,
		AttemptCount:   attemptCount,
		MaxConcurrency: maxConcurrency,
		Timeout:        timeout,
		DryRun:         dryRun,
	}, nil
}

func loadInventoryDocument(
	inventoryFileText string,
	adapter core.InventoryAdapter,
	adapterBinaryText string,
) (inventory.Document, error) {
	if adapter != "" {
		document, err := inventory.LoadWithAdapter(inventoryFileText, adapter, inventory.AdapterOptions{
			ExecutablePath: adapterBinaryText,
		})
		if err != nil {
			return inventory.Document{}, fmt.Errorf("load --inventory-file %q: %w", inventoryFileText, err)
		}
		return document, nil
	}

	document, err := inventory.Load(inventoryFileText)
	if err != nil {
		return inventory.Document{}, fmt.Errorf("load --inventory-file %q: %w", inventoryFileText, err)
	}
	return document, nil
}

func parseTargetsFileRemoteScope(
	targetsFileText string,
	ports []int,
	profile RemoteProfile,
	maxHosts int,
	maxAttempts int,
	maxConcurrency int,
	timeout time.Duration,
	dryRun bool,
) (RemoteScope, error) {
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
	attemptCount, err := remoteAttemptCount(len(hosts), len(ports))
	if err != nil {
		return RemoteScope{}, err
	}
	if attemptCount > maxAttempts {
		return RemoteScope{}, fmt.Errorf("--targets-file expands to %d host:port attempts, which exceeds --max-attempts=%d", attemptCount, maxAttempts)
	}

	return RemoteScope{
		InputKind:      RemoteScopeInputKindTargetsFile,
		TargetsFile:    targetsFileText,
		Hosts:          hosts,
		Ports:          ports,
		Profile:        profile,
		MaxHosts:       maxHosts,
		HostCount:      len(hosts),
		MaxAttempts:    maxAttempts,
		AttemptCount:   attemptCount,
		MaxConcurrency: maxConcurrency,
		Timeout:        timeout,
		DryRun:         dryRun,
	}, nil
}

func parseCIDRRemoteScope(
	cidrText string,
	ports []int,
	profile RemoteProfile,
	maxHosts int,
	maxAttempts int,
	maxConcurrency int,
	timeout time.Duration,
	dryRun bool,
) (RemoteScope, error) {
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
	attemptCount, err := remoteAttemptCount(hostCount, len(ports))
	if err != nil {
		return RemoteScope{}, err
	}
	if attemptCount > maxAttempts {
		return RemoteScope{}, fmt.Errorf("--cidr expands to %d host:port attempts, which exceeds --max-attempts=%d", attemptCount, maxAttempts)
	}

	return RemoteScope{
		InputKind:      RemoteScopeInputKindCIDR,
		CIDR:           prefix,
		Ports:          ports,
		Profile:        profile,
		MaxHosts:       maxHosts,
		HostCount:      hostCount,
		MaxAttempts:    maxAttempts,
		AttemptCount:   attemptCount,
		MaxConcurrency: maxConcurrency,
		Timeout:        timeout,
		DryRun:         dryRun,
	}, nil
}

func parseInventoryAdapter(raw string) (core.InventoryAdapter, error) {
	adapterText := strings.ToLower(strings.TrimSpace(raw))
	if adapterText == "" {
		return "", nil
	}

	adapter := core.InventoryAdapter(adapterText)
	if !inventory.HasAdapter(adapter) {
		return "", fmt.Errorf("unsupported --adapter %q", raw)
	}

	return adapter, nil
}

func resolveInventoryAdapter(path string, raw string) (core.InventoryAdapter, error) {
	if strings.TrimSpace(raw) != "" {
		return parseInventoryAdapter(raw)
	}

	return inventory.DetectAdapter(path), nil
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

func remoteAttemptCount(hostCount int, portCount int) (int, error) {
	return safeMultiplyCount(hostCount, portCount, "expanded remote scope")
}

func inventoryAttemptCount(targets []RemoteScopeTarget) (int, error) {
	total := 0
	for _, target := range targets {
		next, err := safeAddCount(total, len(target.Ports), "inventory-backed remote scope")
		if err != nil {
			return 0, err
		}
		total = next
	}

	return total, nil
}

func safeMultiplyCount(left int, right int, label string) (int, error) {
	if left < 0 || right < 0 {
		return 0, fmt.Errorf("%s count must not be negative", label)
	}
	if left == 0 || right == 0 {
		return 0, nil
	}

	maxInt := int(^uint(0) >> 1)
	if left > maxInt/right {
		return 0, fmt.Errorf("%s count overflowed", label)
	}

	return left * right, nil
}

func safeAddCount(current int, increment int, label string) (int, error) {
	if current < 0 || increment < 0 {
		return 0, fmt.Errorf("%s count must not be negative", label)
	}

	maxInt := int(^uint(0) >> 1)
	if increment > maxInt-current {
		return 0, fmt.Errorf("%s count overflowed", label)
	}

	return current + increment, nil
}

func parseRemoteTargetsFile(path string) ([]string, error) {
	// #nosec G304 -- targets files are explicit operator-provided CLI inputs.
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
	host := normalizeRemoteScopeHost(raw)
	target, err := ValidateTarget(Target{
		Host: host,
		Port: 1,
	})
	if err != nil {
		return "", err
	}

	return normalizeRemoteScopeHost(target.Host), nil
}

func remoteHostKey(host string) string {
	normalized := normalizeRemoteScopeHost(host)
	if address, err := netip.ParseAddr(normalized); err == nil {
		return address.String()
	}

	return strings.ToLower(normalized)
}

func normalizeRemoteScopeHost(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) >= 2 && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		if address, err := netip.ParseAddr(strings.TrimSpace(trimmed[1 : len(trimmed)-1])); err == nil {
			return address.String()
		}
	}
	if address, err := netip.ParseAddr(trimmed); err == nil {
		return address.String()
	}

	return trimmed
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

func assertValidRemoteScope(scope RemoteScope) {
	if !debugassert.Enabled {
		return
	}

	debugassert.That(scope.MaxHosts >= 0, "remote scope MaxHosts must not be negative")
	debugassert.That(scope.MaxAttempts >= 0, "remote scope MaxAttempts must not be negative")
	debugassert.That(scope.MaxConcurrency >= 0, "remote scope MaxConcurrency must not be negative")
	debugassert.That(scope.HostCount >= 0, "remote scope HostCount must not be negative")
	debugassert.That(scope.AttemptCount >= 0, "remote scope AttemptCount must not be negative")
	debugassert.That(scope.HostCount <= scope.MaxHosts, "remote scope HostCount exceeds MaxHosts")
	debugassert.That(scope.AttemptCount <= scope.MaxAttempts, "remote scope AttemptCount exceeds MaxAttempts")
	debugassert.That(scope.Timeout >= 0, "remote scope Timeout must not be negative")

	switch scope.InputKind {
	case RemoteScopeInputKindCIDR:
		debugassert.That(scope.CIDR.IsValid(), "cidr scope must contain a valid prefix")
		debugassert.That(len(scope.Ports) > 0, "cidr scope must contain ports")
		debugassert.That(len(scope.Hosts) == 0, "cidr scope must not contain host list")
		debugassert.That(len(scope.Targets) == 0, "cidr scope must not contain inventory targets")
	case RemoteScopeInputKindTargetsFile:
		debugassert.That(scope.TargetsFile != "", "targets-file scope must include targets file")
		debugassert.That(len(scope.Ports) > 0, "targets-file scope must contain ports")
		debugassert.That(len(scope.Hosts) > 0, "targets-file scope must contain hosts")
		debugassert.That(len(scope.Targets) == 0, "targets-file scope must not contain inventory targets")
	case RemoteScopeInputKindInventoryFile:
		debugassert.That(scope.InventoryFile != "", "inventory-file scope must include inventory file")
		debugassert.That(len(scope.Targets) > 0, "inventory-file scope must contain compiled targets")
		debugassert.That(len(scope.Hosts) == 0, "inventory-file scope must not contain plain host list")
	default:
		debugassert.That(false, "unknown remote scope input kind %q", scope.InputKind)
	}

	for index, port := range scope.Ports {
		debugassert.That(port >= 1 && port <= 65535, "remote scope port %d is invalid", port)
		if index > 0 {
			debugassert.That(scope.Ports[index-1] < port, "remote scope ports must be strictly increasing")
		}
	}

	for _, host := range scope.Hosts {
		debugassert.That(strings.TrimSpace(host) != "", "remote scope hosts must not contain blanks")
	}

	for _, target := range scope.Targets {
		debugassert.That(strings.TrimSpace(target.Host) != "", "remote scope targets must not have blank hosts")
		debugassert.That(len(target.Ports) > 0, "remote scope inventory target must have ports")
		for index, port := range target.Ports {
			debugassert.That(port >= 1 && port <= 65535, "remote scope inventory target port %d is invalid", port)
			if index > 0 {
				debugassert.That(target.Ports[index-1] < port, "remote scope inventory target ports must be strictly increasing")
			}
		}
	}
}
