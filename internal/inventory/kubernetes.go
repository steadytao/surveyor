package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/steadytao/surveyor/internal/core"
	"gopkg.in/yaml.v3"
)

func init() {
	if err := RegisterAdapter(kubernetesIngressV1Adapter{}); err != nil {
		panic(err)
	}
}

type kubernetesIngressV1Adapter struct{}

type kubernetesManifest struct {
	APIVersion string                `yaml:"apiVersion" json:"apiVersion"`
	Kind       string                `yaml:"kind" json:"kind"`
	Metadata   kubernetesMetadata    `yaml:"metadata" json:"metadata"`
	Spec       kubernetesIngressSpec `yaml:"spec" json:"spec"`
	Items      []kubernetesManifest  `yaml:"items" json:"items"`
}

type kubernetesMetadata struct {
	Name      string `yaml:"name" json:"name"`
	Namespace string `yaml:"namespace" json:"namespace"`
}

type kubernetesIngressSpec struct {
	IngressClassName string                    `yaml:"ingressClassName" json:"ingressClassName"`
	DefaultBackend   *kubernetesIngressBackend `yaml:"defaultBackend" json:"defaultBackend"`
	Rules            []kubernetesIngressRule   `yaml:"rules" json:"rules"`
	TLS              []kubernetesIngressTLS    `yaml:"tls" json:"tls"`
}

type kubernetesIngressRule struct {
	Host string              `yaml:"host" json:"host"`
	HTTP *kubernetesHTTPRule `yaml:"http" json:"http"`
}

type kubernetesHTTPRule struct {
	Paths []kubernetesHTTPPath `yaml:"paths" json:"paths"`
}

type kubernetesHTTPPath struct {
	Path     string                   `yaml:"path" json:"path"`
	PathType string                   `yaml:"pathType" json:"pathType"`
	Backend  kubernetesIngressBackend `yaml:"backend" json:"backend"`
}

type kubernetesIngressBackend struct {
	Service  *kubernetesIngressService `yaml:"service" json:"service"`
	Resource *kubernetesObjectRef      `yaml:"resource" json:"resource"`
}

type kubernetesIngressService struct {
	Name string                   `yaml:"name" json:"name"`
	Port kubernetesServicePortRef `yaml:"port" json:"port"`
}

type kubernetesServicePortRef struct {
	Name   string `yaml:"name" json:"name"`
	Number int    `yaml:"number" json:"number"`
}

type kubernetesObjectRef struct {
	APIGroup  string `yaml:"apiGroup" json:"apiGroup"`
	Kind      string `yaml:"kind" json:"kind"`
	Name      string `yaml:"name" json:"name"`
	Namespace string `yaml:"namespace" json:"namespace"`
}

type kubernetesIngressTLS struct {
	Hosts      []string `yaml:"hosts" json:"hosts"`
	SecretName string   `yaml:"secretName" json:"secretName"`
}

type kubernetesHostEntry struct {
	ports      map[int]struct{}
	provenance []core.InventoryProvenance
	warnings   []core.InventoryAdapterWarning
}

func (kubernetesIngressV1Adapter) Name() core.InventoryAdapter {
	return core.InventoryAdapterKubernetesIngressV1
}

func (kubernetesIngressV1Adapter) Parse(data []byte, format core.InventorySourceFormat, sourceName string, _ AdapterOptions) (Document, error) {
	manifests, err := parseKubernetesManifests(data, format)
	if err != nil {
		return Document{}, err
	}

	entries := make([]Entry, 0)
	supportedIngressFound := false
	for index, manifest := range manifests {
		documentPath := fmt.Sprintf("documents[%d]", index)
		documentEntries, found, err := collectKubernetesManifestEntries(manifest, format, sourceName, documentPath)
		if err != nil {
			return Document{}, err
		}
		if found {
			supportedIngressFound = true
		}
		entries = append(entries, documentEntries...)
	}

	if !supportedIngressFound {
		return Document{}, fmt.Errorf("kubernetes-ingress-v1 adapter requires networking.k8s.io/v1 Ingress manifests")
	}
	if len(entries) == 0 {
		return Document{}, fmt.Errorf("kubernetes-ingress-v1 adapter could not derive any concrete remote targets from %q", sourceName)
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

func parseKubernetesManifests(data []byte, format core.InventorySourceFormat) ([]kubernetesManifest, error) {
	switch format {
	case core.InventorySourceFormatYAML:
		return parseKubernetesYAMLManifests(data)
	case core.InventorySourceFormatJSON:
		return parseKubernetesJSONManifests(data)
	default:
		return nil, fmt.Errorf("kubernetes-ingress-v1 adapter requires YAML or JSON input")
	}
}

func parseKubernetesYAMLManifests(data []byte) ([]kubernetesManifest, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	manifests := make([]kubernetesManifest, 0)

	for {
		var manifest kubernetesManifest
		if err := decoder.Decode(&manifest); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parse Kubernetes YAML manifest: %w", err)
		}
		if manifest.Kind == "" && manifest.APIVersion == "" && len(manifest.Items) == 0 {
			continue
		}
		manifests = append(manifests, manifest)
	}

	return manifests, nil
}

func parseKubernetesJSONManifests(data []byte) ([]kubernetesManifest, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("parse Kubernetes JSON manifest: input must not be empty")
	}

	if trimmed[0] == '[' {
		var manifests []kubernetesManifest
		if err := json.Unmarshal(trimmed, &manifests); err != nil {
			return nil, fmt.Errorf("parse Kubernetes JSON manifest list: %w", err)
		}
		return manifests, nil
	}

	var manifest kubernetesManifest
	if err := json.Unmarshal(trimmed, &manifest); err != nil {
		return nil, fmt.Errorf("parse Kubernetes JSON manifest: %w", err)
	}

	return []kubernetesManifest{manifest}, nil
}

func collectKubernetesManifestEntries(manifest kubernetesManifest, format core.InventorySourceFormat, sourceName string, recordPath string) ([]Entry, bool, error) {
	kind := strings.TrimSpace(manifest.Kind)
	switch kind {
	case "":
		return nil, false, nil
	case "List":
		entries := make([]Entry, 0)
		found := false
		for index, item := range manifest.Items {
			itemEntries, itemFound, err := collectKubernetesManifestEntries(item, format, sourceName, fmt.Sprintf("%s.items[%d]", recordPath, index))
			if err != nil {
				return nil, false, err
			}
			if itemFound {
				found = true
			}
			entries = append(entries, itemEntries...)
		}
		return entries, found, nil
	case "Ingress":
		if strings.TrimSpace(manifest.APIVersion) != "networking.k8s.io/v1" {
			return nil, false, fmt.Errorf("kubernetes-ingress-v1 adapter requires apiVersion networking.k8s.io/v1 for %s", recordPath)
		}
		entries, err := buildKubernetesIngressEntries(manifest, format, sourceName, recordPath)
		return entries, true, err
	default:
		return nil, false, nil
	}
}

func buildKubernetesIngressEntries(manifest kubernetesManifest, format core.InventorySourceFormat, sourceName string, recordPath string) ([]Entry, error) {
	name := strings.TrimSpace(manifest.Metadata.Name)
	if name == "" {
		return nil, fmt.Errorf("%s.metadata.name must not be empty", recordPath)
	}

	namespace := strings.TrimSpace(manifest.Metadata.Namespace)
	if namespace == "" {
		namespace = "default"
	}

	sourceObject := fmt.Sprintf("Ingress/%s/%s", namespace, name)
	baseWarnings := []core.InventoryAdapterWarning{
		kubernetesWarning(
			"ingress-controller-required",
			"Ingress effective exposure and TLS behaviour depend on the ingress controller; the manifest alone does not prove live external exposure.",
			sourceName,
			sourceObject,
			recordPath,
			classEvidence(manifest.Spec.IngressClassName),
		),
	}
	if strings.TrimSpace(manifest.Spec.IngressClassName) == "" {
		baseWarnings = append(baseWarnings, kubernetesWarning(
			"ingress-class-unspecified",
			"The Ingress manifest omits ingressClassName, so controller selection depends on cluster defaults or controller-specific behaviour.",
			sourceName,
			sourceObject,
			recordPath+".spec",
		))
	}

	entriesByHost := map[string]*kubernetesHostEntry{}
	order := make([]string, 0)
	ensureHost := func(host string) *kubernetesHostEntry {
		if entry, ok := entriesByHost[host]; ok {
			return entry
		}

		entry := &kubernetesHostEntry{ports: map[int]struct{}{}}
		entriesByHost[host] = entry
		order = append(order, host)
		return entry
	}

	tlsHosts := map[string]struct{}{}
	for tlsIndex, tlsEntry := range manifest.Spec.TLS {
		for hostIndex, rawHost := range tlsEntry.Hosts {
			sourceRecord := fmt.Sprintf("%s.spec.tls[%d].hosts[%d]", recordPath, tlsIndex, hostIndex)
			host, ok := normalizeKubernetesIngressHost(rawHost)
			if !ok {
				baseWarnings = append(baseWarnings, kubernetesWarning(
					"non-concrete-host-ignored",
					"The Ingress manifest contains a host that Surveyor cannot map to a concrete remote target.",
					sourceName,
					sourceObject,
					sourceRecord,
					"host="+strings.TrimSpace(rawHost),
				))
				continue
			}

			hostEntry := ensureHost(host)
			hostEntry.ports[443] = struct{}{}
			hostEntry.provenance = append(hostEntry.provenance, kubernetesProvenance(sourceName, sourceRecord, sourceObject, format))
			tlsHosts[host] = struct{}{}
		}
	}

	for ruleIndex, rule := range manifest.Spec.Rules {
		sourceRecord := fmt.Sprintf("%s.spec.rules[%d]", recordPath, ruleIndex)
		if strings.TrimSpace(rule.Host) == "" {
			baseWarnings = append(baseWarnings, kubernetesWarning(
				"hostless-rule-ignored",
				"The Ingress manifest contains a rule without a concrete host, so Surveyor cannot map it to a concrete remote target.",
				sourceName,
				sourceObject,
				sourceRecord,
			))
			continue
		}

		host, ok := normalizeKubernetesIngressHost(rule.Host)
		if !ok {
			baseWarnings = append(baseWarnings, kubernetesWarning(
				"non-concrete-host-ignored",
				"The Ingress manifest contains a host that Surveyor cannot map to a concrete remote target.",
				sourceName,
				sourceObject,
				sourceRecord,
				"host="+strings.TrimSpace(rule.Host),
			))
			continue
		}

		hostEntry := ensureHost(host)
		hostEntry.ports[80] = struct{}{}
		hostEntry.provenance = append(hostEntry.provenance, kubernetesProvenance(sourceName, sourceRecord, sourceObject, format))
		if _, ok := tlsHosts[host]; !ok {
			hostEntry.warnings = append(hostEntry.warnings, kubernetesWarning(
				"host-without-declared-tls",
				"The Ingress manifest declares this host in a routing rule without a matching TLS host, so Surveyor maps it only to port 80.",
				sourceName,
				sourceObject,
				sourceRecord,
				"host="+host,
			))
		}
	}

	if len(entriesByHost) == 0 {
		return nil, nil
	}

	entries := make([]Entry, 0, len(order))
	for _, host := range order {
		hostEntry := entriesByHost[host]
		ports := make([]int, 0, len(hostEntry.ports))
		for port := range hostEntry.ports {
			ports = append(ports, port)
		}
		sort.Ints(ports)

		entries = append(entries, Entry{
			Host:            host,
			Ports:           ports,
			Provenance:      append([]core.InventoryProvenance(nil), hostEntry.provenance...),
			AdapterWarnings: mergeAdapterWarnings(baseWarnings, hostEntry.warnings),
		})
	}

	return entries, nil
}

func normalizeKubernetesIngressHost(raw string) (string, bool) {
	hostText := strings.TrimSpace(raw)
	if hostText == "" {
		return "", false
	}
	if strings.Contains(hostText, "*") || strings.Contains(hostText, "{") || strings.Contains(hostText, "}") {
		return "", false
	}

	return normalizeHost(hostText), true
}

func kubernetesProvenance(sourceName string, sourceRecord string, sourceObject string, format core.InventorySourceFormat) core.InventoryProvenance {
	return core.InventoryProvenance{
		SourceKind:   core.InventorySourceKindInventoryFile,
		SourceFormat: format,
		SourceName:   sourceName,
		SourceRecord: sourceRecord,
		Adapter:      core.InventoryAdapterKubernetesIngressV1,
		SourceObject: sourceObject,
	}
}

func kubernetesWarning(code string, summary string, sourceName string, sourceObject string, sourceRecord string, extraEvidence ...string) core.InventoryAdapterWarning {
	evidence := []string{
		"adapter=kubernetes-ingress-v1",
		"source_name=" + sourceName,
		"source_object=" + sourceObject,
		"source_record=" + sourceRecord,
	}
	for _, item := range extraEvidence {
		if strings.TrimSpace(item) == "" {
			continue
		}
		evidence = append(evidence, item)
	}

	return core.InventoryAdapterWarning{
		Code:     code,
		Summary:  summary,
		Evidence: evidence,
	}
}

func classEvidence(raw string) string {
	className := strings.TrimSpace(raw)
	if className == "" {
		return ""
	}
	return "ingress_class_name=" + className
}
