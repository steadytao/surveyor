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

	if !result.Reachable {
		t.Fatalf("result.Reachable = false, want true; errors = %v", result.Errors)
	}
	if result.Name != "primary-site" {
		t.Fatalf("result.Name = %q, want %q", result.Name, "primary-site")
	}
	if result.Host != host {
		t.Fatalf("result.Host = %q, want %q", result.Host, host)
	}
	if result.Port != portNumber {
		t.Fatalf("result.Port = %d, want %d", result.Port, portNumber)
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
	if result.LeafKeyAlgorithm != "rsa" {
		t.Fatalf("result.LeafKeyAlgorithm = %q, want %q", result.LeafKeyAlgorithm, "rsa")
	}
	if result.LeafKeySize != 2048 {
		t.Fatalf("result.LeafKeySize = %d, want %d", result.LeafKeySize, 2048)
	}
	if result.LeafSignatureAlgorithm != "sha256-rsa" {
		t.Fatalf("result.LeafSignatureAlgorithm = %q, want %q", result.LeafSignatureAlgorithm, "sha256-rsa")
	}
	if got, want := len(result.CertificateChain), 1; got != want {
		t.Fatalf("len(result.CertificateChain) = %d, want %d", got, want)
	}
	if result.CertificateChain[0].Subject != serverCert.Subject.String() {
		t.Fatalf("result.CertificateChain[0].Subject = %q, want %q", result.CertificateChain[0].Subject, serverCert.Subject.String())
	}
	if result.CertificateChain[0].Issuer != serverCert.Issuer.String() {
		t.Fatalf("result.CertificateChain[0].Issuer = %q, want %q", result.CertificateChain[0].Issuer, serverCert.Issuer.String())
	}
	if result.CertificateChain[0].SerialNumber != serverCert.SerialNumber.String() {
		t.Fatalf("result.CertificateChain[0].SerialNumber = %q, want %q", result.CertificateChain[0].SerialNumber, serverCert.SerialNumber.String())
	}
	if !result.CertificateChain[0].NotBefore.Equal(serverCert.NotBefore.UTC()) {
		t.Fatalf("result.CertificateChain[0].NotBefore = %v, want %v", result.CertificateChain[0].NotBefore, serverCert.NotBefore.UTC())
	}
	if !result.CertificateChain[0].NotAfter.Equal(serverCert.NotAfter.UTC()) {
		t.Fatalf("result.CertificateChain[0].NotAfter = %v, want %v", result.CertificateChain[0].NotAfter, serverCert.NotAfter.UTC())
	}
	if got, want := len(result.CertificateChain[0].DNSNames), len(serverCert.DNSNames); got != want {
		t.Fatalf("len(result.CertificateChain[0].DNSNames) = %d, want %d", got, want)
	}
	for index, dnsName := range serverCert.DNSNames {
		if result.CertificateChain[0].DNSNames[index] != dnsName {
			t.Fatalf("result.CertificateChain[0].DNSNames[%d] = %q, want %q", index, result.CertificateChain[0].DNSNames[index], dnsName)
		}
	}
	if result.CertificateChain[0].PublicKeyAlgorithm != "rsa" {
		t.Fatalf("result.CertificateChain[0].PublicKeyAlgorithm = %q, want %q", result.CertificateChain[0].PublicKeyAlgorithm, "rsa")
	}
	if result.CertificateChain[0].PublicKeySize != 2048 {
		t.Fatalf("result.CertificateChain[0].PublicKeySize = %d, want %d", result.CertificateChain[0].PublicKeySize, 2048)
	}
	if result.CertificateChain[0].SignatureAlgorithm != "sha256-rsa" {
		t.Fatalf("result.CertificateChain[0].SignatureAlgorithm = %q, want %q", result.CertificateChain[0].SignatureAlgorithm, "sha256-rsa")
	}
	if result.CertificateChain[0].IsCA != serverCert.IsCA {
		t.Fatalf("result.CertificateChain[0].IsCA = %t, want %t", result.CertificateChain[0].IsCA, serverCert.IsCA)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("len(result.Errors) = %d, want 0; errors = %v", len(result.Errors), result.Errors)
	}
	if got, want := len(result.Findings), 1; got != want {
		t.Fatalf("len(result.Findings) = %d, want %d; findings = %#v", got, want, result.Findings)
	}
	if result.Findings[0].Code != "classical-certificate-identity" {
		t.Fatalf("result.Findings[0].Code = %q, want %q", result.Findings[0].Code, "classical-certificate-identity")
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("len(result.Warnings) = %d, want 0; warnings = %v", len(result.Warnings), result.Warnings)
	}
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

	if result.Reachable {
		t.Fatal("result.Reachable = true, want false")
	}
	if result.Classification != classificationUnreachable {
		t.Fatalf("result.Classification = %q, want %q", result.Classification, classificationUnreachable)
	}
	if result.TLSVersion != "" {
		t.Fatalf("result.TLSVersion = %q, want empty", result.TLSVersion)
	}
	if result.CipherSuite != "" {
		t.Fatalf("result.CipherSuite = %q, want empty", result.CipherSuite)
	}
	if result.LeafKeyAlgorithm != "" {
		t.Fatalf("result.LeafKeyAlgorithm = %q, want empty", result.LeafKeyAlgorithm)
	}
	if result.LeafKeySize != 0 {
		t.Fatalf("result.LeafKeySize = %d, want 0", result.LeafKeySize)
	}
	if result.LeafSignatureAlgorithm != "" {
		t.Fatalf("result.LeafSignatureAlgorithm = %q, want empty", result.LeafSignatureAlgorithm)
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
	if result.Findings[0].Code != "target-unreachable" {
		t.Fatalf("result.Findings[0].Code = %q, want %q", result.Findings[0].Code, "target-unreachable")
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
