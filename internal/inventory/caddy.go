package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

func init() {
	if err := RegisterAdapter(caddyAdapter{}); err != nil {
		panic(err)
	}
}

type caddyAdapter struct{}

type caddyConfig struct {
	Apps caddyApps `json:"apps"`
}

type caddyApps struct {
	HTTP *caddyHTTPApp `json:"http"`
}

type caddyHTTPApp struct {
	Servers map[string]caddyServer `json:"servers"`
}

type caddyServer struct {
	Listen []string     `json:"listen"`
	Routes []caddyRoute `json:"routes"`
}

type caddyRoute struct {
	ID     string            `json:"@id"`
	Match  []caddyHostMatch  `json:"match"`
	Handle []caddyRouteBlock `json:"handle"`
	Routes []caddyRoute      `json:"routes"`
}

type caddyRouteBlock struct {
	Handler string       `json:"handler"`
	Routes  []caddyRoute `json:"routes"`
}

type caddyHostMatch struct {
	Host []string `json:"host"`
}

const caddyAdaptTimeout = 30 * time.Second

func (caddyAdapter) Name() core.InventoryAdapter {
	return core.InventoryAdapterCaddy
}

func (caddyAdapter) Parse(data []byte, format core.InventorySourceFormat, sourceName string, options AdapterOptions) (Document, error) {
	var adaptationWarnings []core.InventoryAdapterWarning
	switch format {
	case core.InventorySourceFormatJSON:
	case core.InventorySourceFormatCaddyfile:
		adaptedJSON, warnings, err := adaptCaddyfileToJSON(data, sourceName, options)
		if err != nil {
			return Document{}, err
		}
		data = adaptedJSON
		adaptationWarnings = warnings
	default:
		return Document{}, fmt.Errorf("caddy adapter requires JSON or Caddyfile input")
	}

	var config caddyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return Document{}, fmt.Errorf("parse Caddy JSON inventory: %w", err)
	}
	if config.Apps.HTTP == nil || len(config.Apps.HTTP.Servers) == 0 {
		return Document{}, fmt.Errorf("caddy adapter requires apps.http.servers in the input document")
	}

	serverNames := make([]string, 0, len(config.Apps.HTTP.Servers))
	for serverName := range config.Apps.HTTP.Servers {
		serverNames = append(serverNames, serverName)
	}
	sort.Strings(serverNames)

	entries := make([]Entry, 0)
	for _, serverName := range serverNames {
		server := config.Apps.HTTP.Servers[serverName]
		ports, serverWarnings := parseCaddyListenerPorts(serverName, format, sourceName, server.Listen)
		if len(ports) == 0 {
			continue
		}

		baseWarnings := mergeAdapterWarnings(adaptationWarnings, serverWarnings)
		entries = append(entries, collectCaddyRouteEntries(serverName, format, sourceName, ports, baseWarnings, nil, server.Routes, "apps.http.servers."+serverName+".routes")...)
	}

	if len(entries) == 0 {
		return Document{}, fmt.Errorf("caddy adapter could not derive any concrete remote targets from %q", sourceName)
	}

	deduplicated, err := deduplicateEntries(entries)
	if err != nil {
		return Document{}, err
	}

	return Document{
		Format:     format,
		SourceName: sourceName,
		Entries:    deduplicated,
	}, nil
}

func collectCaddyRouteEntries(serverName string, format core.InventorySourceFormat, sourceName string, ports []int, serverWarnings []core.InventoryAdapterWarning, inheritedHosts []string, routes []caddyRoute, recordPrefix string) []Entry {
	entries := make([]Entry, 0)
	for routeIndex, route := range routes {
		recordPath := fmt.Sprintf("%s[%d]", recordPrefix, routeIndex)
		explicitHosts, hostWarnings := extractCaddyRouteHosts(serverName, format, sourceName, route, recordPath)
		effectiveHosts := resolveCaddyHosts(inheritedHosts, explicitHosts)

		if len(explicitHosts) > 0 && len(effectiveHosts) > 0 {
			sourceObject := caddySourceObject(serverName, route, recordPath)
			warnings := append(cloneAdapterWarnings(serverWarnings), hostWarnings...)
			for _, host := range effectiveHosts {
				entries = append(entries, Entry{
					Host:            host,
					Ports:           append([]int(nil), ports...),
					Provenance:      []core.InventoryProvenance{caddyProvenance(sourceName, recordPath, sourceObject, format)},
					AdapterWarnings: cloneAdapterWarnings(warnings),
				})
			}
		}

		nextHosts := inheritedHosts
		if len(explicitHosts) > 0 {
			nextHosts = effectiveHosts
		}

		if len(route.Routes) > 0 {
			entries = append(entries, collectCaddyRouteEntries(serverName, format, sourceName, ports, serverWarnings, nextHosts, route.Routes, recordPath+".routes")...)
		}
		for handleIndex, handle := range route.Handle {
			if len(handle.Routes) == 0 {
				continue
			}
			handlePrefix := fmt.Sprintf("%s.handle[%d].routes", recordPath, handleIndex)
			entries = append(entries, collectCaddyRouteEntries(serverName, format, sourceName, ports, serverWarnings, nextHosts, handle.Routes, handlePrefix)...)
		}
	}

	return entries
}

func parseCaddyListenerPorts(serverName string, format core.InventorySourceFormat, sourceName string, listen []string) ([]int, []core.InventoryAdapterWarning) {
	seen := make(map[int]struct{}, len(listen))
	ports := make([]int, 0, len(listen))
	warnings := make([]core.InventoryAdapterWarning, 0)

	for _, raw := range listen {
		listener := strings.TrimSpace(raw)
		if listener == "" {
			continue
		}

		network, _, portText := splitCaddyNetworkAddress(listener)
		if network != "" && network != "tcp" && network != "tcp4" && network != "tcp6" {
			warnings = append(warnings, core.InventoryAdapterWarning{
				Code:    "non-tcp-listener-ignored",
				Summary: "Caddy listener does not use TCP and cannot be mapped into Surveyor remote scope.",
				Evidence: []string{
					"adapter=caddy",
					"source_format=" + string(format),
					"source_name=" + sourceName,
					"source_object=server " + serverName,
					"listener=" + listener,
				},
			})
			continue
		}

		if portText == "" {
			warnings = append(warnings, core.InventoryAdapterWarning{
				Code:    "listener-without-port-ignored",
				Summary: "Caddy listener does not declare a concrete port and cannot be mapped into Surveyor remote scope.",
				Evidence: []string{
					"adapter=caddy",
					"source_format=" + string(format),
					"source_name=" + sourceName,
					"source_object=server " + serverName,
					"listener=" + listener,
				},
			})
			continue
		}

		start, end, ok := parseCaddyPortRange(portText)
		if !ok {
			warnings = append(warnings, core.InventoryAdapterWarning{
				Code:    "listener-port-ignored",
				Summary: "Caddy listener uses a port form that Surveyor cannot map cleanly.",
				Evidence: []string{
					"adapter=caddy",
					"source_format=" + string(format),
					"source_name=" + sourceName,
					"source_object=server " + serverName,
					"listener=" + listener,
				},
			})
			continue
		}

		for port := start; port <= end; port++ {
			if _, exists := seen[port]; exists {
				continue
			}
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}

	sort.Ints(ports)
	return ports, warnings
}

func adaptCaddyfileToJSON(data []byte, sourceName string, options AdapterOptions) ([]byte, []core.InventoryAdapterWarning, error) {
	binary, err := resolveCaddyBinary(options)
	if err != nil {
		return nil, nil, err
	}

	args := []string{"adapt", "--adapter", "caddyfile", "--config"}
	useFilePath := caddyfilePathExists(sourceName)
	if useFilePath {
		args = append(args, sourceName)
	} else {
		args = append(args, "-")
	}

	ctx, cancel := context.WithTimeout(context.Background(), caddyAdaptTimeout)
	defer cancel()

	// #nosec G204 -- the adapter binary path is deliberate operator configuration,
	// resolved through Surveyor's adapter contract rather than untrusted network input.
	cmd := exec.CommandContext(ctx, binary, args...)
	if !useFilePath {
		cmd.Stdin = bytes.NewReader(data)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	warnings := translateCaddyAdaptationWarnings(sourceName, stderr.String())
	if ctx.Err() == context.DeadlineExceeded {
		return nil, warnings, fmt.Errorf("caddy adapter timed out while adapting Caddyfile after %s", caddyAdaptTimeout)
	}
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return nil, warnings, fmt.Errorf("adapt Caddyfile inventory: %s", message)
		}
		return nil, warnings, fmt.Errorf("adapt Caddyfile inventory: %w", err)
	}

	return stdout.Bytes(), warnings, nil
}

func resolveCaddyBinary(options AdapterOptions) (string, error) {
	override := strings.TrimSpace(options.ExecutablePath)
	if override != "" {
		path, err := exec.LookPath(override)
		if err != nil {
			return "", fmt.Errorf("caddy adapter could not resolve --adapter-bin %q: %w", override, err)
		}
		return path, nil
	}

	envOverride := strings.TrimSpace(os.Getenv("SURVEYOR_CADDY_BIN"))
	if envOverride != "" {
		path, err := exec.LookPath(envOverride)
		if err != nil {
			return "", fmt.Errorf("caddy adapter could not resolve SURVEYOR_CADDY_BIN %q: %w", envOverride, err)
		}
		return path, nil
	}

	path, err := exec.LookPath("caddy")
	if err == nil {
		return path, nil
	}

	if path, ok := detectCommonCaddyBinary(); ok {
		return path, nil
	}

	return "", fmt.Errorf("caddy adapter could not find the Caddy executable, checked --adapter-bin, SURVEYOR_CADDY_BIN, PATH and common install locations")
}

func caddyfilePathExists(sourceName string) bool {
	sourceName = strings.TrimSpace(sourceName)
	if sourceName == "" {
		return false
	}

	info, err := os.Stat(sourceName)
	return err == nil && !info.IsDir()
}

func translateCaddyAdaptationWarnings(sourceName string, stderrText string) []core.InventoryAdapterWarning {
	lines := splitNonEmptyLines(stderrText)
	if len(lines) == 0 {
		return nil
	}

	translated := make([]core.InventoryAdapterWarning, 0, len(lines))
	for _, line := range lines {
		evidence := []string{
			"adapter=caddy",
			"source_format=caddyfile",
		}
		if strings.TrimSpace(sourceName) != "" {
			evidence = append(evidence, "source_name="+sourceName)
		}

		translated = append(translated, core.InventoryAdapterWarning{
			Code:     "caddyfile-adaptation-warning",
			Summary:  line,
			Evidence: evidence,
		})
	}

	return translated
}

func splitNonEmptyLines(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	trimmed := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		trimmed = append(trimmed, line)
	}

	if len(trimmed) == 0 {
		return nil
	}

	return trimmed
}

func detectCommonCaddyBinary() (string, bool) {
	for _, candidate := range commonCaddyBinaryCandidates() {
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, true
		}
	}

	return "", false
}

func commonCaddyBinaryCandidates() []string {
	if runtime.GOOS == "windows" {
		return existingCaddyCandidates([]string{
			filepath.Join(os.Getenv("ProgramFiles"), "Caddy", "caddy.exe"),
			filepath.Join(os.Getenv("ProgramFiles"), "caddy", "caddy.exe"),
			filepath.Join(os.Getenv("ProgramData"), "chocolatey", "bin", "caddy.exe"),
			filepath.Join(os.Getenv("ChocolateyInstall"), "bin", "caddy.exe"),
			filepath.Join(os.Getenv("USERPROFILE"), "scoop", "shims", "caddy.exe"),
		})
	}

	return existingCaddyCandidates([]string{
		"/usr/bin/caddy",
		"/usr/local/bin/caddy",
		"/opt/homebrew/bin/caddy",
		"/home/linuxbrew/.linuxbrew/bin/caddy",
		"/snap/bin/caddy",
	})
}

func existingCaddyCandidates(candidates []string) []string {
	filtered := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		filtered = append(filtered, candidate)
	}

	return filtered
}

func splitCaddyNetworkAddress(raw string) (string, string, string) {
	network := ""
	address := raw
	if slash := strings.Index(raw, "/"); slash >= 0 {
		candidate := raw[:slash]
		switch candidate {
		case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip", "ip4", "ip6", "unix", "unixgram", "unixpacket":
			network = candidate
			address = raw[slash+1:]
		}
	}

	if network == "unix" || network == "unixgram" || network == "unixpacket" {
		return network, address, ""
	}

	if strings.HasPrefix(address, "[") {
		if closing := strings.Index(address, "]"); closing >= 0 && closing+1 < len(address) && address[closing+1] == ':' {
			return network, address[:closing+1], address[closing+2:]
		}
	}

	if colon := strings.LastIndex(address, ":"); colon >= 0 {
		return network, address[:colon], address[colon+1:]
	}

	return network, address, ""
}

func parseCaddyPortRange(raw string) (int, int, bool) {
	if raw == "" {
		return 0, 0, false
	}

	parts := strings.Split(raw, "-")
	if len(parts) > 2 {
		return 0, 0, false
	}

	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 1 || start > 65535 {
		return 0, 0, false
	}
	end := start
	if len(parts) == 2 {
		end, err = strconv.Atoi(parts[1])
		if err != nil || end < start || end > 65535 {
			return 0, 0, false
		}
	}

	return start, end, true
}

func extractCaddyRouteHosts(serverName string, format core.InventorySourceFormat, sourceName string, route caddyRoute, recordPath string) ([]string, []core.InventoryAdapterWarning) {
	seen := map[string]struct{}{}
	hosts := make([]string, 0)
	warnings := make([]core.InventoryAdapterWarning, 0)
	sourceObject := caddySourceObject(serverName, route, recordPath)

	for _, matcher := range route.Match {
		for _, rawHost := range matcher.Host {
			hostText := strings.TrimSpace(rawHost)
			if hostText == "" {
				continue
			}
			if strings.Contains(hostText, "*") || strings.Contains(hostText, "{") || strings.Contains(hostText, "}") {
				warnings = append(warnings, core.InventoryAdapterWarning{
					Code:    "non-concrete-host-ignored",
					Summary: "Caddy route contains a wildcard or placeholder host that Surveyor cannot map to a concrete remote target.",
					Evidence: []string{
						"adapter=caddy",
						"source_format=" + string(format),
						"source_name=" + sourceName,
						"source_object=" + sourceObject,
						"host=" + hostText,
					},
				})
				continue
			}

			host := normalizeHost(hostText)
			if _, exists := seen[host]; exists {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}

	sort.Strings(hosts)
	return hosts, warnings
}

func resolveCaddyHosts(inherited []string, explicit []string) []string {
	if len(explicit) == 0 {
		return append([]string(nil), inherited...)
	}
	if len(inherited) == 0 {
		return append([]string(nil), explicit...)
	}

	allowed := make(map[string]struct{}, len(inherited))
	for _, host := range inherited {
		allowed[host] = struct{}{}
	}

	resolved := make([]string, 0, len(explicit))
	for _, host := range explicit {
		if _, ok := allowed[host]; ok {
			resolved = append(resolved, host)
		}
	}

	return resolved
}

func caddyProvenance(sourceName string, sourceRecord string, sourceObject string, format core.InventorySourceFormat) core.InventoryProvenance {
	return core.InventoryProvenance{
		SourceKind:   core.InventorySourceKindInventoryFile,
		SourceFormat: format,
		SourceName:   sourceName,
		SourceRecord: sourceRecord,
		Adapter:      core.InventoryAdapterCaddy,
		SourceObject: sourceObject,
	}
}

func caddySourceObject(serverName string, route caddyRoute, sourceRecord string) string {
	if route.ID != "" {
		return fmt.Sprintf("server %s @id %s", serverName, route.ID)
	}

	prefix := "apps.http.servers." + serverName + "."
	label := strings.TrimPrefix(sourceRecord, prefix)
	return fmt.Sprintf("server %s %s", serverName, label)
}
