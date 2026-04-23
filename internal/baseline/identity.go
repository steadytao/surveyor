// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/steadytao/surveyor/internal/core"
)

// TargetResultIdentityKey returns the stable comparison key for an explicit TLS
// target result.
func TargetResultIdentityKey(result core.TargetResult) string {
	return normalizeHost(result.Host) + "|" + strconv.Itoa(result.Port)
}

// DiscoveredEndpointIdentityKey returns the stable comparison key for a
// discovered endpoint.
func DiscoveredEndpointIdentityKey(endpoint core.DiscoveredEndpoint) string {
	return strings.Join([]string{
		string(endpoint.ScopeKind),
		normalizeHost(endpoint.Host),
		strconv.Itoa(endpoint.Port),
		strings.ToLower(endpoint.Transport),
	}, "|")
}

// AuditResultIdentityKey returns the stable comparison key for an audit result.
func AuditResultIdentityKey(result core.AuditResult) string {
	return DiscoveredEndpointIdentityKey(result.DiscoveredEndpoint)
}

func normalizeHost(host string) string {
	trimmed := strings.TrimSpace(host)
	if address, err := netip.ParseAddr(trimmed); err == nil {
		return address.String()
	}

	return strings.ToLower(trimmed)
}
