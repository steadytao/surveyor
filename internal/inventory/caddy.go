package inventory

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

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

func (caddyAdapter) Name() core.InventoryAdapter {
	return core.InventoryAdapterCaddy
}

func (caddyAdapter) Parse(data []byte, format core.InventorySourceFormat, sourceName string) (Document, error) {
	if format != core.InventorySourceFormatJSON {
		return Document{}, fmt.Errorf("caddy adapter requires JSON input")
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
		ports, serverWarnings := parseCaddyListenerPorts(serverName, sourceName, server.Listen)
		if len(ports) == 0 {
			continue
		}

		entries = append(entries, collectCaddyRouteEntries(serverName, sourceName, ports, serverWarnings, nil, server.Routes, "apps.http.servers."+serverName+".routes")...)
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

func collectCaddyRouteEntries(serverName string, sourceName string, ports []int, serverWarnings []core.InventoryAdapterWarning, inheritedHosts []string, routes []caddyRoute, recordPrefix string) []Entry {
	entries := make([]Entry, 0)
	for routeIndex, route := range routes {
		recordPath := fmt.Sprintf("%s[%d]", recordPrefix, routeIndex)
		explicitHosts, hostWarnings := extractCaddyRouteHosts(serverName, sourceName, route, recordPath)
		effectiveHosts := resolveCaddyHosts(inheritedHosts, explicitHosts)

		if len(explicitHosts) > 0 && len(effectiveHosts) > 0 {
			sourceObject := caddySourceObject(serverName, route, recordPath)
			warnings := append(cloneAdapterWarnings(serverWarnings), hostWarnings...)
			for _, host := range effectiveHosts {
				entries = append(entries, Entry{
					Host:            host,
					Ports:           append([]int(nil), ports...),
					Provenance:      []core.InventoryProvenance{caddyProvenance(sourceName, recordPath, sourceObject)},
					AdapterWarnings: cloneAdapterWarnings(warnings),
				})
			}
		}

		nextHosts := inheritedHosts
		if len(explicitHosts) > 0 {
			nextHosts = effectiveHosts
		}

		if len(route.Routes) > 0 {
			entries = append(entries, collectCaddyRouteEntries(serverName, sourceName, ports, serverWarnings, nextHosts, route.Routes, recordPath+".routes")...)
		}
		for handleIndex, handle := range route.Handle {
			if len(handle.Routes) == 0 {
				continue
			}
			handlePrefix := fmt.Sprintf("%s.handle[%d].routes", recordPath, handleIndex)
			entries = append(entries, collectCaddyRouteEntries(serverName, sourceName, ports, serverWarnings, nextHosts, handle.Routes, handlePrefix)...)
		}
	}

	return entries
}

func parseCaddyListenerPorts(serverName string, sourceName string, listen []string) ([]int, []core.InventoryAdapterWarning) {
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

func extractCaddyRouteHosts(serverName string, sourceName string, route caddyRoute, recordPath string) ([]string, []core.InventoryAdapterWarning) {
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

func caddyProvenance(sourceName string, sourceRecord string, sourceObject string) core.InventoryProvenance {
	return core.InventoryProvenance{
		SourceKind:   core.InventorySourceKindInventoryFile,
		SourceFormat: core.InventorySourceFormatJSON,
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

func caddySourceDisplayName(sourceName string) string {
	base := filepath.Base(sourceName)
	if strings.TrimSpace(base) != "" {
		return base
	}
	return sourceName
}
