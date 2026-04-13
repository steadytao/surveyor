package tlsinventory

import (
	"strings"

	"github.com/steadytao/surveyor/internal/core"
)

const (
	classificationClassicalCertificates = "classical_certificates"
	classificationLegacyTLSExposure     = "legacy_tls_exposure"
	classificationManualReviewRequired  = "manual_review_required"
	classificationModernTLSClassicalID  = "modern_tls_classical_identity"
	classificationUnreachable           = "unreachable"
)

func classifyResult(result core.TargetResult) core.TargetResult {
	switch {
	case !result.Reachable:
		result.Classification = classificationUnreachable
		result.Findings = append(result.Findings, core.Finding{
			Code:     "target-unreachable",
			Severity: core.SeverityMedium,
			Summary:  "The target could not be reached with a TLS connection.",
			Evidence: append([]string(nil), result.Errors...),
			Recommendation: "Confirm the endpoint, network path, and whether a TLS service is actually available " +
				"before treating this target as assessed.",
		})
		return result
	case len(result.CertificateChain) == 0 || result.LeafKeyAlgorithm == "" || result.LeafSignatureAlgorithm == "":
		result.Classification = classificationManualReviewRequired
		result.Findings = append(result.Findings, core.Finding{
			Code:           "incomplete-certificate-observation",
			Severity:       core.SeverityMedium,
			Summary:        "The TLS service was reachable, but the certificate evidence is incomplete.",
			Evidence:       certificateObservationEvidence(result),
			Recommendation: "Review the endpoint manually before drawing migration conclusions from this result.",
		})
		return result
	case !isClassicalIdentityAlgorithm(result.LeafKeyAlgorithm) || !isClassicalSignatureAlgorithm(result.LeafSignatureAlgorithm):
		result.Classification = classificationManualReviewRequired
		result.Findings = append(result.Findings, core.Finding{
			Code:     "unsupported-certificate-identity",
			Severity: core.SeverityMedium,
			Summary:  "The observed certificate identity does not match the currently recognised classical set.",
			Evidence: []string{
				"leaf_key_algorithm=" + result.LeafKeyAlgorithm,
				"leaf_signature_algorithm=" + result.LeafSignatureAlgorithm,
			},
			Recommendation: "Review the endpoint manually and extend the classification rules only when the new identity " +
				"handling is understood and tested.",
		})
		return result
	}

	if isLegacyTLSVersion(result.TLSVersion) {
		result.Classification = classificationLegacyTLSExposure
		result.Findings = append(result.Findings,
			core.Finding{
				Code:     "legacy-tls-version",
				Severity: core.SeverityHigh,
				Summary:  "The service negotiated a legacy TLS version.",
				Evidence: []string{"tls_version=" + result.TLSVersion},
				Recommendation: "Prioritise upgrading the service to TLS 1.2 or TLS 1.3 before treating its transport " +
					"posture as modern.",
			},
			classicalCertificateFinding(result),
		)
		return result
	}

	if isModernTLSVersion(result.TLSVersion) {
		result.Classification = classificationModernTLSClassicalID
		result.Findings = append(result.Findings, classicalCertificateFinding(result))
		return result
	}

	result.Classification = classificationClassicalCertificates
	result.Findings = append(result.Findings, classicalCertificateFinding(result))
	return result
}

func classicalCertificateFinding(result core.TargetResult) core.Finding {
	return core.Finding{
		Code:     "classical-certificate-identity",
		Severity: core.SeverityMedium,
		Summary:  "The observed certificate identity remains classical.",
		Evidence: []string{
			"leaf_key_algorithm=" + result.LeafKeyAlgorithm,
			"leaf_signature_algorithm=" + result.LeafSignatureAlgorithm,
		},
		Recommendation: "Inventory certificate replacement and related PKI dependencies as part of migration planning.",
	}
}

func certificateObservationEvidence(result core.TargetResult) []string {
	evidence := []string{}

	if result.TLSVersion != "" {
		evidence = append(evidence, "tls_version="+result.TLSVersion)
	}
	if result.CipherSuite != "" {
		evidence = append(evidence, "cipher_suite="+result.CipherSuite)
	}
	evidence = append(evidence, result.Warnings...)

	if len(evidence) == 0 {
		return []string{"certificate metadata unavailable"}
	}

	return evidence
}

func isLegacyTLSVersion(version string) bool {
	switch version {
	case "TLS 1.0", "TLS 1.1", "SSL 3.0":
		return true
	default:
		return false
	}
}

func isModernTLSVersion(version string) bool {
	switch version {
	case "TLS 1.2", "TLS 1.3":
		return true
	default:
		return false
	}
}

func isClassicalIdentityAlgorithm(name string) bool {
	switch strings.ToLower(name) {
	case "rsa", "dsa", "ecdsa", "ed25519":
		return true
	default:
		return false
	}
}

func isClassicalSignatureAlgorithm(name string) bool {
	normalized := strings.ToLower(name)

	return strings.Contains(normalized, "rsa") ||
		strings.Contains(normalized, "dsa") ||
		strings.Contains(normalized, "ecdsa") ||
		strings.Contains(normalized, "ed25519")
}
