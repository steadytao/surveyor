package tlsinventory

import (
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/core"
)

func TestClassifyResult(t *testing.T) {
	t.Parallel()

	scannedAt := time.Date(2026, time.April, 14, 8, 0, 0, 0, time.UTC)
	baseReachableResult := core.TargetResult{
		Host:                   "example.com",
		Port:                   443,
		ScannedAt:              scannedAt,
		Reachable:              true,
		LeafKeyAlgorithm:       "rsa",
		LeafKeySize:            2048,
		LeafSignatureAlgorithm: "sha256-rsa",
		CertificateChain: []core.CertificateRef{
			{
				Subject:            "CN=example.com",
				Issuer:             "CN=Example CA",
				PublicKeyAlgorithm: "rsa",
				PublicKeySize:      2048,
				SignatureAlgorithm: "sha256-rsa",
			},
		},
	}

	testCases := []struct {
		name               string
		input              core.TargetResult
		wantClassification string
		wantFindingCodes   []string
	}{
		{
			name: "unreachable",
			input: core.TargetResult{
				Host:      "example.com",
				Port:      443,
				ScannedAt: scannedAt,
				Reachable: false,
				Errors:    []string{"tls connection failed: connection attempt failed"},
			},
			wantClassification: classificationUnreachable,
			wantFindingCodes:   []string{"target-unreachable"},
		},
		{
			name: "missing certificate evidence",
			input: core.TargetResult{
				Host:        "example.com",
				Port:        443,
				ScannedAt:   scannedAt,
				Reachable:   true,
				TLSVersion:  "TLS 1.3",
				CipherSuite: "TLS_AES_128_GCM_SHA256",
				Warnings:    []string{"no peer certificates were presented"},
			},
			wantClassification: classificationManualReviewRequired,
			wantFindingCodes:   []string{"incomplete-certificate-observation"},
		},
		{
			name: "legacy tls exposure",
			input: func() core.TargetResult {
				result := baseReachableResult
				result.TLSVersion = "TLS 1.0"
				result.CipherSuite = "TLS_RSA_WITH_AES_128_CBC_SHA"
				return result
			}(),
			wantClassification: classificationLegacyTLSExposure,
			wantFindingCodes:   []string{"legacy-tls-version", "classical-certificate-identity"},
		},
		{
			name: "modern tls classical identity",
			input: func() core.TargetResult {
				result := baseReachableResult
				result.TLSVersion = "TLS 1.3"
				result.CipherSuite = "TLS_AES_128_GCM_SHA256"
				return result
			}(),
			wantClassification: classificationModernTLSClassicalID,
			wantFindingCodes:   []string{"classical-certificate-identity"},
		},
		{
			name:               "classical certificates with unknown tls version",
			input:              baseReachableResult,
			wantClassification: classificationClassicalCertificates,
			wantFindingCodes:   []string{"classical-certificate-identity"},
		},
		{
			name: "unsupported identity algorithm",
			input: func() core.TargetResult {
				result := baseReachableResult
				result.TLSVersion = "TLS 1.3"
				result.LeafKeyAlgorithm = "ml-dsa"
				return result
			}(),
			wantClassification: classificationManualReviewRequired,
			wantFindingCodes:   []string{"unsupported-certificate-identity"},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			result := classifyResult(testCase.input)

			if result.Classification != testCase.wantClassification {
				t.Fatalf("result.Classification = %q, want %q", result.Classification, testCase.wantClassification)
			}

			if got, want := len(result.Findings), len(testCase.wantFindingCodes); got != want {
				t.Fatalf("len(result.Findings) = %d, want %d; findings = %#v", got, want, result.Findings)
			}

			for index, wantCode := range testCase.wantFindingCodes {
				if result.Findings[index].Code != wantCode {
					t.Fatalf("result.Findings[%d].Code = %q, want %q", index, result.Findings[index].Code, wantCode)
				}
			}
		})
	}
}
