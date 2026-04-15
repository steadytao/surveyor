package core

import "time"

// EndpointScopeKind records whether an observed endpoint came from local or
// remote scope.
type EndpointScopeKind string

const (
	EndpointScopeKindLocal  EndpointScopeKind = "local"
	EndpointScopeKindRemote EndpointScopeKind = "remote"
)

// DiscoveryHint is a conservative protocol hint derived from observed facts.
type DiscoveryHint struct {
	Protocol   string   `json:"protocol"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

// ReportScopeInputKind records how a remote report's declared scope was
// supplied.
type ReportScopeInputKind string

const (
	ReportScopeInputKindCIDR        ReportScopeInputKind = "cidr"
	ReportScopeInputKindTargetsFile ReportScopeInputKind = "targets_file"
)

// ReportScope records the declared scope a discovery or audit report covers.
type ReportScope struct {
	ScopeKind   EndpointScopeKind    `json:"scope_kind"`
	InputKind   ReportScopeInputKind `json:"input_kind,omitempty"`
	CIDR        string               `json:"cidr,omitempty"`
	TargetsFile string               `json:"targets_file,omitempty"`
	Ports       []int                `json:"ports,omitempty"`
}

// ReportExecution records the execution settings that materially shaped a
// discovery or audit run.
type ReportExecution struct {
	Profile        string `json:"profile,omitempty"`
	MaxHosts       int    `json:"max_hosts,omitempty"`
	MaxConcurrency int    `json:"max_concurrency,omitempty"`
	Timeout        string `json:"timeout,omitempty"`
}

// DiscoveredEndpoint records one observed endpoint within declared scope and
// any best-effort enrichment that applies to that scope kind.
type DiscoveredEndpoint struct {
	ScopeKind   EndpointScopeKind `json:"scope_kind"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Transport   string            `json:"transport"`
	State       string            `json:"state"`
	PID         int               `json:"pid,omitempty"`
	ProcessName string            `json:"process_name,omitempty"`
	Executable  string            `json:"executable,omitempty"`
	Hints       []DiscoveryHint   `json:"hints,omitempty"`
	Warnings    []string          `json:"warnings,omitempty"`
	Errors      []string          `json:"errors,omitempty"`
}

// DiscoverySummary contains aggregate counts derived from discovered endpoints.
type DiscoverySummary struct {
	TotalEndpoints int            `json:"total_endpoints"`
	TCPEndpoints   int            `json:"tcp_endpoints"`
	UDPEndpoints   int            `json:"udp_endpoints"`
	HintBreakdown  map[string]int `json:"hint_breakdown,omitempty"`
}

// DiscoveryReport is the top-level canonical discovery report.
type DiscoveryReport struct {
	GeneratedAt time.Time            `json:"generated_at"`
	Scope       *ReportScope         `json:"scope,omitempty"`
	Execution   *ReportExecution     `json:"execution,omitempty"`
	Results     []DiscoveredEndpoint `json:"results"`
	Summary     DiscoverySummary     `json:"summary"`
}
