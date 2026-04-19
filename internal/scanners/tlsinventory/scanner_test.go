package tlsinventory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
)

func TestScanTargetSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	server.StartTLS()
	defer server.Close()

	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}

	scannedAt := time.Date(2026, time.April, 13, 13, 0, 0, 0, time.UTC)
	scanner := Scanner{
		Now: func() time.Time { return scannedAt },
	}

	result := scanner.ScanTarget(context.Background(), config.Target{
		Name: "primary-site",
		Host: host,
		Port: portNumber,
	})

	serverCert := server.Certificate()

	assertSuccessfulScanTargetResult(t, result, "primary-site", host, portNumber, scannedAt)
	assertCertificateChainMatchesServer(t, result, serverCert)
	assertScanTargetFindings(t, result, "classical-certificate-identity")
}

func TestScanTargetFailure(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	scanner := Scanner{
		Timeout: 2 * time.Second,
		Now: func() time.Time {
			return time.Date(2026, time.April, 13, 13, 30, 0, 0, time.UTC)
		},
	}

	result := scanner.ScanTarget(context.Background(), config.Target{
		Host: host,
		Port: portNumber,
	})

	assertFailedScanTargetResult(t, result, "target-unreachable")
}

func assertSuccessfulScanTargetResult(
	t *testing.T,
	result core.TargetResult,
	name string,
	host string,
	port int,
	scannedAt time.Time,
) {
	t.Helper()

	if !result.Reachable {
		t.Fatalf("result.Reachable = false, want true; errors = %v", result.Errors)
	}
	if result.Name != name {
		t.Fatalf("result.Name = %q, want %q", result.Name, name)
	}
	if result.Host != host {
		t.Fatalf("result.Host = %q, want %q", result.Host, host)
	}
	if result.Port != port {
		t.Fatalf("result.Port = %d, want %d", result.Port, port)
	}
	if !result.ScannedAt.Equal(scannedAt) {
		t.Fatalf("result.ScannedAt = %v, want %v", result.ScannedAt, scannedAt)
	}
	if result.Address == "" {
		t.Fatal("result.Address = empty, want populated remote address")
	}
	if result.TLSVersion != "TLS 1.2" {
		t.Fatalf("result.TLSVersion = %q, want %q", result.TLSVersion, "TLS 1.2")
	}
	if result.CipherSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("result.CipherSuite = %q, want %q", result.CipherSuite, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	}
	if result.Classification != classificationModernTLSClassicalID {
		t.Fatalf("result.Classification = %q, want %q", result.Classification, classificationModernTLSClassicalID)
	}
	if result.LeafKeyAlgorithm != "rsa" || result.LeafKeySize != 2048 || result.LeafSignatureAlgorithm != "sha256-rsa" {
		t.Fatalf("result key details = algorithm=%q size=%d signature=%q, want rsa/2048/sha256-rsa", result.LeafKeyAlgorithm, result.LeafKeySize, result.LeafSignatureAlgorithm)
	}
}

func assertCertificateChainMatchesServer(t *testing.T, result core.TargetResult, serverCert *x509.Certificate) {
	t.Helper()

	if got, want := len(result.CertificateChain), 1; got != want {
		t.Fatalf("len(result.CertificateChain) = %d, want %d", got, want)
	}

	leaf := result.CertificateChain[0]
	if leaf.Subject != serverCert.Subject.String() || leaf.Issuer != serverCert.Issuer.String() || leaf.SerialNumber != serverCert.SerialNumber.String() {
		t.Fatalf("certificate identity = %#v, want subject=%q issuer=%q serial=%q", leaf, serverCert.Subject.String(), serverCert.Issuer.String(), serverCert.SerialNumber.String())
	}
	if !leaf.NotBefore.Equal(serverCert.NotBefore.UTC()) || !leaf.NotAfter.Equal(serverCert.NotAfter.UTC()) {
		t.Fatalf("certificate validity = %v..%v, want %v..%v", leaf.NotBefore, leaf.NotAfter, serverCert.NotBefore.UTC(), serverCert.NotAfter.UTC())
	}
	if got, want := len(leaf.DNSNames), len(serverCert.DNSNames); got != want {
		t.Fatalf("len(result.CertificateChain[0].DNSNames) = %d, want %d", got, want)
	}
	for index, dnsName := range serverCert.DNSNames {
		if leaf.DNSNames[index] != dnsName {
			t.Fatalf("result.CertificateChain[0].DNSNames[%d] = %q, want %q", index, leaf.DNSNames[index], dnsName)
		}
	}
	if leaf.PublicKeyAlgorithm != "rsa" || leaf.PublicKeySize != 2048 || leaf.SignatureAlgorithm != "sha256-rsa" {
		t.Fatalf("certificate crypto = algorithm=%q size=%d signature=%q, want rsa/2048/sha256-rsa", leaf.PublicKeyAlgorithm, leaf.PublicKeySize, leaf.SignatureAlgorithm)
	}
	if leaf.IsCA != serverCert.IsCA {
		t.Fatalf("result.CertificateChain[0].IsCA = %t, want %t", leaf.IsCA, serverCert.IsCA)
	}
}

func assertScanTargetFindings(t *testing.T, result core.TargetResult, findingCode string) {
	t.Helper()

	if len(result.Errors) != 0 {
		t.Fatalf("len(result.Errors) = %d, want 0; errors = %v", len(result.Errors), result.Errors)
	}
	if got, want := len(result.Findings), 1; got != want {
		t.Fatalf("len(result.Findings) = %d, want %d; findings = %#v", got, want, result.Findings)
	}
	if result.Findings[0].Code != findingCode {
		t.Fatalf("result.Findings[0].Code = %q, want %q", result.Findings[0].Code, findingCode)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("len(result.Warnings) = %d, want 0; warnings = %v", len(result.Warnings), result.Warnings)
	}
}

func assertFailedScanTargetResult(t *testing.T, result core.TargetResult, findingCode string) {
	t.Helper()

	if result.Reachable {
		t.Fatal("result.Reachable = true, want false")
	}
	if result.Classification != classificationUnreachable {
		t.Fatalf("result.Classification = %q, want %q", result.Classification, classificationUnreachable)
	}
	if result.TLSVersion != "" || result.CipherSuite != "" || result.LeafKeyAlgorithm != "" || result.LeafKeySize != 0 || result.LeafSignatureAlgorithm != "" {
		t.Fatalf("unexpected TLS details on failed result: %#v", result)
	}
	if len(result.CertificateChain) != 0 {
		t.Fatalf("len(result.CertificateChain) = %d, want 0", len(result.CertificateChain))
	}
	if len(result.Errors) != 1 {
		t.Fatalf("len(result.Errors) = %d, want 1; errors = %v", len(result.Errors), result.Errors)
	}
	if got, want := len(result.Findings), 1; got != want {
		t.Fatalf("len(result.Findings) = %d, want %d; findings = %#v", got, want, result.Findings)
	}
	if result.Findings[0].Code != findingCode {
		t.Fatalf("result.Findings[0].Code = %q, want %q", result.Findings[0].Code, findingCode)
	}
	if !strings.Contains(result.Errors[0], "tls connection failed:") {
		t.Fatalf("result.Errors[0] = %q, want tls connection failure prefix", result.Errors[0])
	}
}

func TestScanTargetSelfSignedCertificate(t *testing.T) {
	t.Parallel()

	server := newFixtureTLSServer(t, certificateFixture{
		commonName: "localhost",
		dnsNames:   []string{"localhost"},
		notBefore:  time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC),
		notAfter:   time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC),
		serial:     42,
	})
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}

	result := Scanner{
		Now: func() time.Time { return time.Date(2026, time.April, 14, 9, 0, 0, 0, time.UTC) },
	}.ScanTarget(context.Background(), config.Target{
		Host: "localhost",
		Port: portNumber,
	})

	if !result.Reachable {
		t.Fatalf("result.Reachable = false, want true; errors = %v", result.Errors)
	}
	if result.Classification != classificationModernTLSClassicalID {
		t.Fatalf("result.Classification = %q, want %q", result.Classification, classificationModernTLSClassicalID)
	}
	if got, want := len(result.CertificateChain), 1; got != want {
		t.Fatalf("len(result.CertificateChain) = %d, want %d", got, want)
	}
	if result.CertificateChain[0].Subject != result.CertificateChain[0].Issuer {
		t.Fatalf("subject/issuer mismatch for self-signed cert: subject=%q issuer=%q", result.CertificateChain[0].Subject, result.CertificateChain[0].Issuer)
	}
	if result.CertificateChain[0].DNSNames[0] != "localhost" {
		t.Fatalf("result.CertificateChain[0].DNSNames[0] = %q, want %q", result.CertificateChain[0].DNSNames[0], "localhost")
	}
}

func TestScanTargetExpiredCertificate(t *testing.T) {
	t.Parallel()

	server := newFixtureTLSServer(t, certificateFixture{
		commonName: "localhost",
		dnsNames:   []string{"localhost"},
		notBefore:  time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
		notAfter:   time.Date(2025, time.February, 1, 0, 0, 0, 0, time.UTC),
		serial:     43,
	})
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}

	scannedAt := time.Date(2026, time.April, 14, 9, 30, 0, 0, time.UTC)
	result := Scanner{
		Now: func() time.Time { return scannedAt },
	}.ScanTarget(context.Background(), config.Target{
		Host: "localhost",
		Port: portNumber,
	})

	if !result.Reachable {
		t.Fatalf("result.Reachable = false, want true; errors = %v", result.Errors)
	}
	if result.Classification != classificationModernTLSClassicalID {
		t.Fatalf("result.Classification = %q, want %q", result.Classification, classificationModernTLSClassicalID)
	}
	if !result.CertificateChain[0].NotAfter.Before(scannedAt) {
		t.Fatalf("result.CertificateChain[0].NotAfter = %v, want date before %v", result.CertificateChain[0].NotAfter, scannedAt)
	}
}

func TestScanTargetHostnameMismatchCertificate(t *testing.T) {
	t.Parallel()

	server := newFixtureTLSServer(t, certificateFixture{
		commonName: "example.com",
		dnsNames:   []string{"example.com"},
		notBefore:  time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC),
		notAfter:   time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC),
		serial:     44,
	})
	defer server.Close()

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}

	result := Scanner{
		Now: func() time.Time { return time.Date(2026, time.April, 14, 10, 0, 0, 0, time.UTC) },
	}.ScanTarget(context.Background(), config.Target{
		Host: "localhost",
		Port: portNumber,
	})

	if !result.Reachable {
		t.Fatalf("result.Reachable = false, want true; errors = %v", result.Errors)
	}
	if result.Classification != classificationModernTLSClassicalID {
		t.Fatalf("result.Classification = %q, want %q", result.Classification, classificationModernTLSClassicalID)
	}
	if result.CertificateChain[0].DNSNames[0] != "example.com" {
		t.Fatalf("result.CertificateChain[0].DNSNames[0] = %q, want %q", result.CertificateChain[0].DNSNames[0], "example.com")
	}
}

type certificateFixture struct {
	commonName string
	dnsNames   []string
	notBefore  time.Time
	notAfter   time.Time
	serial     int64
}

func newFixtureTLSServer(t *testing.T, fixture certificateFixture) *httptest.Server {
	t.Helper()

	certificate := newSelfSignedCertificate(t, fixture)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		Certificates: []tls.Certificate{certificate},
	}
	server.StartTLS()

	return server
}

func newSelfSignedCertificate(t *testing.T, fixture certificateFixture) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(fixture.serial),
		Subject: pkix.Name{
			CommonName: fixture.commonName,
		},
		Issuer: pkix.Name{
			CommonName: fixture.commonName,
		},
		NotBefore:             fixture.notBefore,
		NotAfter:              fixture.notAfter,
		DNSNames:              append([]string(nil), fixture.dnsNames...),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certificateDER},
		PrivateKey:  privateKey,
	}
}
