package core

import "time"

type DiscoveryHint struct {
	Protocol   string   `json:"protocol"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type DiscoveredEndpoint struct {
	Address     string          `json:"address"`
	Port        int             `json:"port"`
	Transport   string          `json:"transport"`
	State       string          `json:"state"`
	PID         int             `json:"pid,omitempty"`
	ProcessName string          `json:"process_name,omitempty"`
	Executable  string          `json:"executable,omitempty"`
	Hints       []DiscoveryHint `json:"hints,omitempty"`
	Warnings    []string        `json:"warnings,omitempty"`
	Errors      []string        `json:"errors,omitempty"`
}

type DiscoverySummary struct {
	TotalEndpoints int            `json:"total_endpoints"`
	TCPEndpoints   int            `json:"tcp_endpoints"`
	UDPEndpoints   int            `json:"udp_endpoints"`
	HintBreakdown  map[string]int `json:"hint_breakdown,omitempty"`
}

type DiscoveryReport struct {
	GeneratedAt time.Time            `json:"generated_at"`
	Results     []DiscoveredEndpoint `json:"results"`
	Summary     DiscoverySummary     `json:"summary"`
}
