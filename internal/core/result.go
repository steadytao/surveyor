package core

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Finding struct {
	Code           string   `json:"code"`
	Severity       Severity `json:"severity"`
	Summary        string   `json:"summary"`
	Evidence       []string `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
}

type CertificateRef struct {
	Subject            string    `json:"subject,omitempty"`
	Issuer             string    `json:"issuer,omitempty"`
	SerialNumber       string    `json:"serial_number,omitempty"`
	NotBefore          time.Time `json:"not_before,omitempty"`
	NotAfter           time.Time `json:"not_after,omitempty"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm,omitempty"`
	PublicKeySize      int       `json:"public_key_size,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	IsCA               bool      `json:"is_ca,omitempty"`
}

type TargetResult struct {
	Name                   string           `json:"name,omitempty"`
	Host                   string           `json:"host"`
	Port                   int              `json:"port"`
	Address                string           `json:"address,omitempty"`
	ScannedAt              time.Time        `json:"scanned_at"`
	Reachable              bool             `json:"reachable"`
	TLSVersion             string           `json:"tls_version,omitempty"`
	CipherSuite            string           `json:"cipher_suite,omitempty"`
	LeafKeyAlgorithm       string           `json:"leaf_key_algorithm,omitempty"`
	LeafKeySize            int              `json:"leaf_key_size,omitempty"`
	LeafSignatureAlgorithm string           `json:"leaf_signature_algorithm,omitempty"`
	CertificateChain       []CertificateRef `json:"certificate_chain,omitempty"`
	Classification         string           `json:"classification"`
	Findings               []Finding        `json:"findings,omitempty"`
	Warnings               []string         `json:"warnings,omitempty"`
	Errors                 []string         `json:"errors,omitempty"`
}

type Summary struct {
	TotalTargets            int            `json:"total_targets"`
	ReachableTargets        int            `json:"reachable_targets"`
	UnreachableTargets      int            `json:"unreachable_targets"`
	ClassificationBreakdown map[string]int `json:"classification_breakdown,omitempty"`
}

type Report struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Results     []TargetResult `json:"results"`
	Summary     Summary        `json:"summary"`
}
