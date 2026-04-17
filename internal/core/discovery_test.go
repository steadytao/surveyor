package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDiscoveredEndpointJSONShape(t *testing.T) {
	t.Parallel()

	endpoint := DiscoveredEndpoint{
		ScopeKind:   EndpointScopeKindLocal,
		Host:        "0.0.0.0",
		Port:        443,
		Transport:   "tcp",
		State:       "listening",
		PID:         1234,
		ProcessName: "local-service",
		Executable:  "C:\\SurveyorTest\\local-service.exe",
		Hints: []DiscoveryHint{
			{
				Protocol:   "tls",
				Confidence: "low",
				Evidence:   []string{"transport=tcp", "port=443"},
			},
		},
		Warnings: []string{"sample warning"},
		Errors:   []string{"sample error"},
	}

	data, err := json.Marshal(endpoint)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)
	wantSubstrings := []string{
		`"scope_kind":"local"`,
		`"host":"0.0.0.0"`,
		`"port":443`,
		`"transport":"tcp"`,
		`"state":"listening"`,
		`"pid":1234`,
		`"process_name":"local-service"`,
		`"executable":"C:\\SurveyorTest\\local-service.exe"`,
		`"protocol":"tls"`,
		`"confidence":"low"`,
		`"warnings":["sample warning"]`,
		`"errors":["sample error"]`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestDiscoveredEndpointInventoryAnnotationJSONShapeForCaddyJSON(t *testing.T) {
	t.Parallel()

	endpoint := DiscoveredEndpoint{
		ScopeKind: EndpointScopeKindRemote,
		Host:      "api.example.com",
		Port:      443,
		Transport: "tcp",
		State:     "responsive",
		Inventory: &InventoryAnnotation{
			Ports:       []int{443, 8443},
			Name:        "Payments API",
			Owner:       "payments",
			Environment: "prod",
			Tags:        []string{"external", "critical"},
			Notes:       "Internet-facing service",
			Provenance: []InventoryProvenance{
				{
					SourceKind:   InventorySourceKindInventoryFile,
					SourceFormat: InventorySourceFormatJSON,
					SourceName:   "caddy.json",
					SourceRecord: "servers[0]",
					Adapter:      InventoryAdapterCaddy,
					SourceObject: "site api.example.com",
				},
			},
			AdapterWarnings: []InventoryAdapterWarning{
				{
					Code:     "ambiguous-port",
					Summary:  "The adapted source did not declare one explicit listener port.",
					Evidence: []string{"adapter=caddy", "source_name=caddy.json", "source_object=site api.example.com"},
				},
			},
		},
	}

	data, err := json.Marshal(endpoint)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)
	wantSubstrings := []string{
		`"inventory":{"ports":[443,8443]`,
		`"name":"Payments API"`,
		`"owner":"payments"`,
		`"environment":"prod"`,
		`"tags":["external","critical"]`,
		`"notes":"Internet-facing service"`,
		`"source_kind":"inventory_file"`,
		`"source_format":"json"`,
		`"source_name":"caddy.json"`,
		`"source_record":"servers[0]"`,
		`"adapter":"caddy"`,
		`"source_object":"site api.example.com"`,
		`"adapter_warnings":[{"code":"ambiguous-port"`,
		`"summary":"The adapted source did not declare one explicit listener port."`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestDiscoveredEndpointInventoryAnnotationJSONShapeForKubernetesIngressManifest(t *testing.T) {
	t.Parallel()

	endpoint := DiscoveredEndpoint{
		ScopeKind: EndpointScopeKindRemote,
		Host:      "api.example.com",
		Port:      443,
		Transport: "tcp",
		State:     "responsive",
		Inventory: &InventoryAnnotation{
			Ports:       []int{443},
			Name:        "payments-api",
			Owner:       "payments",
			Environment: "prod",
			Tags:        []string{"external", "ingress"},
			Provenance: []InventoryProvenance{
				{
					SourceKind:   InventorySourceKindInventoryFile,
					SourceFormat: InventorySourceFormatYAML,
					SourceName:   "ingress.yaml",
					SourceRecord: "documents[0]",
					Adapter:      InventoryAdapterKubernetesIngressV1,
					SourceObject: "Ingress/default/payments-api",
				},
			},
			AdapterWarnings: []InventoryAdapterWarning{
				{
					Code:     "controller-specific-behaviour",
					Summary:  "The ingress controller may affect effective exposure and TLS handling.",
					Evidence: []string{"adapter=kubernetes-ingress-v1", "source_name=ingress.yaml", "source_object=Ingress/default/payments-api"},
				},
			},
		},
	}

	data, err := json.Marshal(endpoint)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)
	wantSubstrings := []string{
		`"source_format":"yaml"`,
		`"source_name":"ingress.yaml"`,
		`"source_record":"documents[0]"`,
		`"adapter":"kubernetes-ingress-v1"`,
		`"source_object":"Ingress/default/payments-api"`,
		`"code":"controller-specific-behaviour"`,
		`"summary":"The ingress controller may affect effective exposure and TLS handling."`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestDiscoveryReportJSONShape(t *testing.T) {
	t.Parallel()

	report := DiscoveryReport{
		ReportMetadata: NewReportMetadata(ReportKindDiscovery, ReportScopeKindRemote, "remote discovery within CIDR 10.0.0.0/30 over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 15, 1, 45, 0, 0, time.UTC),
		Scope: &ReportScope{
			ScopeKind: ReportScopeKindRemote,
			InputKind: ReportInputKindCIDR,
			CIDR:      "10.0.0.0/30",
			Ports:     []int{443},
		},
		Results: []DiscoveredEndpoint{
			{
				ScopeKind: EndpointScopeKindLocal,
				Host:      "127.0.0.1",
				Port:      5353,
				Transport: "udp",
				State:     "bound",
			},
		},
		Summary: DiscoverySummary{
			TotalEndpoints: 1,
			UDPEndpoints:   1,
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)
	wantSubstrings := []string{
		`"schema_version":"1.0"`,
		`"tool_version":"dev"`,
		`"report_kind":"discovery"`,
		`"scope_kind":"remote"`,
		`"scope_description":"remote discovery within CIDR 10.0.0.0/30 over ports 443"`,
		`"generated_at":"2026-04-15T01:45:00Z"`,
		`"scope":{"scope_kind":"remote","input_kind":"cidr","cidr":"10.0.0.0/30","ports":[443]}`,
		`"results":[`,
		`"scope_kind":"local"`,
		`"summary":{"total_endpoints":1,"tcp_endpoints":0,"udp_endpoints":1}`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestDiscoveryReportInventoryScopeJSONShape(t *testing.T) {
	t.Parallel()

	report := DiscoveryReport{
		ReportMetadata: NewReportMetadata(ReportKindDiscovery, ReportScopeKindRemote, "remote discovery from inventory file examples/inventory.csv over ports 443"),
		GeneratedAt:    time.Date(2026, time.April, 15, 1, 45, 0, 0, time.UTC),
		Scope: &ReportScope{
			ScopeKind:     ReportScopeKindRemote,
			InputKind:     ReportInputKindInventoryFile,
			InventoryFile: "examples/inventory.csv",
			Ports:         []int{443},
		},
		Results: []DiscoveredEndpoint{
			{
				ScopeKind: EndpointScopeKindRemote,
				Host:      "api.example.com",
				Port:      443,
				Transport: "tcp",
				State:     "responsive",
			},
		},
		Summary: DiscoverySummary{
			TotalEndpoints: 1,
			TCPEndpoints:   1,
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)
	wantSubstrings := []string{
		`"scope_description":"remote discovery from inventory file examples/inventory.csv over ports 443"`,
		`"scope":{"scope_kind":"remote","input_kind":"inventory_file","inventory_file":"examples/inventory.csv","ports":[443]}`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestCloneDiscoveredEndpointClonesInventoryAdapterWarnings(t *testing.T) {
	t.Parallel()

	endpoint := DiscoveredEndpoint{
		ScopeKind: EndpointScopeKindRemote,
		Host:      "api.example.com",
		Port:      443,
		Transport: "tcp",
		State:     "responsive",
		Inventory: &InventoryAnnotation{
			Provenance: []InventoryProvenance{
				{
					SourceKind:   InventorySourceKindInventoryFile,
					SourceFormat: InventorySourceFormatYAML,
					SourceName:   "ingress.yaml",
					SourceRecord: "documents[0]",
					Adapter:      InventoryAdapterKubernetesIngressV1,
					SourceObject: "Ingress/default/payments-api",
				},
			},
			AdapterWarnings: []InventoryAdapterWarning{
				{
					Code:     "controller-specific-behaviour",
					Summary:  "The ingress controller may affect effective exposure and TLS handling.",
					Evidence: []string{"adapter=kubernetes-ingress-v1", "source_object=Ingress/default/payments-api"},
				},
			},
		},
	}

	cloned := CloneDiscoveredEndpoint(endpoint)

	endpoint.Inventory.Provenance[0].SourceObject = "mutated"
	endpoint.Inventory.AdapterWarnings[0].Evidence[0] = "mutated"

	if got, want := cloned.Inventory.Provenance[0].SourceObject, "Ingress/default/payments-api"; got != want {
		t.Fatalf("cloned.Inventory.Provenance[0].SourceObject = %q, want %q", got, want)
	}
	if got, want := cloned.Inventory.AdapterWarnings[0].Evidence[0], "adapter=kubernetes-ingress-v1"; got != want {
		t.Fatalf("cloned.Inventory.AdapterWarnings[0].Evidence[0] = %q, want %q", got, want)
	}
}
