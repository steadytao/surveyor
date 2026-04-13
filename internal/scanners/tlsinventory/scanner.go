package tlsinventory

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/steadytao/surveyor/internal/config"
	"github.com/steadytao/surveyor/internal/core"
)

const DefaultTimeout = 10 * time.Second

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
		return result
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		result.Errors = []string{"tls connection failed: expected *tls.Conn"}
		return result
	}

	state := tlsConn.ConnectionState()
	result.Reachable = true
	result.Address = conn.RemoteAddr().String()
	result.TLSVersion = tls.VersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	return result
}

func serverName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}

	return host
}
