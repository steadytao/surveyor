package tlsinventory

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
)

const DefaultTimeout = 10 * time.Second

var repeatedDashPattern = regexp.MustCompile(`-+`)

type Scanner struct {
	Timeout time.Duration
	Now     func() time.Time
}

func (s Scanner) ScanTarget(ctx context.Context, target config.Target) core.TargetResult {
	scannedAt := time.Now().UTC()
	if s.Now != nil {
		scannedAt = s.Now().UTC()
	}

	result := core.TargetResult{
		Name:      target.Name,
		Host:      target.Host,
		Port:      target.Port,
		ScannedAt: scannedAt,
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	address := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	dialer := &net.Dialer{Timeout: timeout}
	tlsDialer := &tls.Dialer{
		NetDialer: dialer,
		Config: &tls.Config{
			// The collection layer needs to observe the presented service even when
			// certificate validation would fail. Trust and hostname analysis belong
			// in later certificate and classification steps.
			InsecureSkipVerify: true, //nolint:gosec
			ServerName:         serverName(target.Host),
		},
	}

	conn, err := tlsDialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Errors = []string{fmt.Sprintf("tls connection failed: %v", err)}
		return classifyResult(result)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		result.Errors = []string{"tls connection failed: expected *tls.Conn"}
		return classifyResult(result)
	}

	state := tlsConn.ConnectionState()
	result.Reachable = true
	result.Address = conn.RemoteAddr().String()
	result.TLSVersion = tls.VersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.CertificateChain = certificateRefs(state.PeerCertificates)

	if len(state.PeerCertificates) == 0 {
		result.Warnings = append(result.Warnings, "no peer certificates were presented")
		return classifyResult(result)
	}

	leaf := state.PeerCertificates[0]
	result.LeafKeyAlgorithm = publicKeyAlgorithmName(leaf.PublicKeyAlgorithm)
	result.LeafKeySize = publicKeySize(leaf)
	result.LeafSignatureAlgorithm = signatureAlgorithmName(leaf.SignatureAlgorithm)

	return classifyResult(result)
}

func serverName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}

	return host
}

func certificateRefs(peerCertificates []*x509.Certificate) []core.CertificateRef {
	if len(peerCertificates) == 0 {
		return nil
	}

	refs := make([]core.CertificateRef, 0, len(peerCertificates))

	for _, certificate := range peerCertificates {
		if certificate == nil {
			continue
		}

		refs = append(refs, core.CertificateRef{
			Subject:            certificate.Subject.String(),
			Issuer:             certificate.Issuer.String(),
			SerialNumber:       certificate.SerialNumber.String(),
			NotBefore:          certificate.NotBefore.UTC(),
			NotAfter:           certificate.NotAfter.UTC(),
			DNSNames:           append([]string(nil), certificate.DNSNames...),
			PublicKeyAlgorithm: publicKeyAlgorithmName(certificate.PublicKeyAlgorithm),
			PublicKeySize:      publicKeySize(certificate),
			SignatureAlgorithm: signatureAlgorithmName(certificate.SignatureAlgorithm),
			IsCA:               certificate.IsCA,
		})
	}

	if len(refs) == 0 {
		return nil
	}

	return refs
}

func publicKeyAlgorithmName(algorithm x509.PublicKeyAlgorithm) string {
	if algorithm == x509.UnknownPublicKeyAlgorithm {
		return ""
	}

	return strings.ToLower(algorithm.String())
}

func signatureAlgorithmName(algorithm x509.SignatureAlgorithm) string {
	if algorithm == x509.UnknownSignatureAlgorithm {
		return ""
	}

	name := strings.ToLower(algorithm.String())
	name = strings.ReplaceAll(name, " ", "-")

	return repeatedDashPattern.ReplaceAllString(name, "-")
}

func publicKeySize(certificate *x509.Certificate) int {
	if certificate == nil {
		return 0
	}

	switch publicKey := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return publicKey.N.BitLen()
	case *ecdsa.PublicKey:
		return publicKey.Params().BitSize
	case ed25519.PublicKey:
		return len(publicKey) * 8
	default:
		return 0
	}
}
