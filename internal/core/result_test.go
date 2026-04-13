package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTargetResultJSONShape(t *testing.T) {
	t.Parallel()

	scannedAt := time.Date(2026, time.April, 13, 12, 0, 0, 0, time.UTC)
	notBefore := time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)

	result := TargetResult{
		Name:                   "primary-site",
		Host:                   "example.com",
		Port:                   443,
		Address:                "203.0.113.10",
		ScannedAt:              scannedAt,
		Reachable:              true,
		TLSVersion:             "tls1.3",
		CipherSuite:            "TLS_AES_128_GCM_SHA256",
		LeafKeyAlgorithm:       "rsa",
		LeafKeySize:            2048,
		LeafSignatureAlgorithm: "sha256WithRSAEncryption",
		CertificateChain: []CertificateRef{
			{
				Subject:            "CN=example.com",
				Issuer:             "CN=Example Intermediate",
				SerialNumber:       "01",
				NotBefore:          notBefore,
				NotAfter:           notAfter,
				DNSNames:           []string{"example.com", "www.example.com"},
				PublicKeyAlgorithm: "rsa",
				PublicKeySize:      2048,
				SignatureAlgorithm: "sha256WithRSAEncryption",
			},
		},
		Classification: "modern_tls_classical_identity",
		Findings: []Finding{
			{
				Code:           "classical-certificate",
				Severity:       SeverityMedium,
				Summary:        "Leaf certificate remains classical",
				Evidence:       []string{"leaf_key_algorithm=rsa", "leaf_key_size=2048"},
				Recommendation: "Plan certificate replacement work as part of migration.",
			},
		},
		Warnings: []string{"certificate chain was presented without OCSP data"},
		Errors:   []string{"sample error"},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)

	wantSubstrings := []string{
		`"name":"primary-site"`,
		`"host":"example.com"`,
		`"port":443`,
		`"address":"203.0.113.10"`,
		`"scanned_at":"2026-04-13T12:00:00Z"`,
		`"reachable":true`,
		`"tls_version":"tls1.3"`,
		`"cipher_suite":"TLS_AES_128_GCM_SHA256"`,
		`"leaf_key_algorithm":"rsa"`,
		`"leaf_key_size":2048`,
		`"leaf_signature_algorithm":"sha256WithRSAEncryption"`,
		`"certificate_chain":[`,
		`"serial_number":"01"`,
		`"dns_names":["example.com","www.example.com"]`,
		`"classification":"modern_tls_classical_identity"`,
		`"code":"classical-certificate"`,
		`"severity":"medium"`,
		`"warnings":["certificate chain was presented without OCSP data"]`,
		`"errors":["sample error"]`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestTargetResultOmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()

	result := TargetResult{
		Host:           "example.com",
		Port:           443,
		ScannedAt:      time.Date(2026, time.April, 13, 12, 0, 0, 0, time.UTC),
		Reachable:      false,
		Classification: "unreachable",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)

	unwantedSubstrings := []string{
		`"name":`,
		`"address":`,
		`"tls_version":`,
		`"cipher_suite":`,
		`"leaf_key_algorithm":`,
		`"leaf_key_size":`,
		`"leaf_signature_algorithm":`,
		`"certificate_chain":`,
		`"findings":`,
		`"warnings":`,
		`"errors":`,
	}

	for _, substring := range unwantedSubstrings {
		if strings.Contains(jsonText, substring) {
			t.Fatalf("json output unexpectedly contained %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestReportJSONShape(t *testing.T) {
	t.Parallel()

	report := Report{
		GeneratedAt: time.Date(2026, time.April, 13, 12, 30, 0, 0, time.UTC),
		Results: []TargetResult{
			{
				Host:           "example.com",
				Port:           443,
				ScannedAt:      time.Date(2026, time.April, 13, 12, 0, 0, 0, time.UTC),
				Reachable:      true,
				Classification: "classical_only",
			},
		},
		Summary: Summary{
			TotalTargets:       1,
			ReachableTargets:   1,
			UnreachableTargets: 0,
			ClassificationBreakdown: map[string]int{
				"classical_only": 1,
			},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)

	wantSubstrings := []string{
		`"generated_at":"2026-04-13T12:30:00Z"`,
		`"results":[`,
		`"summary":{"total_targets":1,"reachable_targets":1,"unreachable_targets":0,"classification_breakdown":{"classical_only":1}}`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}
