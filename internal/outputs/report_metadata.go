// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package outputs

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/steadytao/surveyor/internal/core"
)

func cloneReportScope(scope *core.ReportScope) *core.ReportScope {
	if scope == nil {
		return nil
	}

	clone := *scope
	clone.Ports = append([]int(nil), scope.Ports...)
	return &clone
}

func cloneReportExecution(execution *core.ReportExecution) *core.ReportExecution {
	if execution == nil {
		return nil
	}

	clone := *execution
	return &clone
}

func buildTLSReportMetadata(scope *core.ReportScope) core.ReportMetadata {
	scopeKind := core.ReportScopeKindExplicit
	if scope != nil && scope.ScopeKind != "" {
		scopeKind = scope.ScopeKind
	}

	return core.NewReportMetadata(core.ReportKindTLSScan, scopeKind, describeTLSScope(scope))
}

func buildDiscoveryReportMetadata(scope *core.ReportScope) core.ReportMetadata {
	scopeKind := core.ReportScopeKindLocal
	if scope != nil && scope.ScopeKind != "" {
		scopeKind = scope.ScopeKind
	}

	return core.NewReportMetadata(core.ReportKindDiscovery, scopeKind, describeDiscoveryScope(scope))
}

func buildAuditReportMetadata(scope *core.ReportScope) core.ReportMetadata {
	scopeKind := core.ReportScopeKindLocal
	if scope != nil && scope.ScopeKind != "" {
		scopeKind = scope.ScopeKind
	}

	return core.NewReportMetadata(core.ReportKindAudit, scopeKind, describeAuditScope(scope))
}

func describeTLSScope(scope *core.ReportScope) string {
	if scope == nil {
		return "explicit TLS targets"
	}

	switch scope.InputKind {
	case core.ReportInputKindConfig:
		return "explicit TLS targets from config"
	case core.ReportInputKindTargets:
		return "explicit TLS targets from command-line targets"
	default:
		return "explicit TLS targets"
	}
}

func describeDiscoveryScope(scope *core.ReportScope) string {
	if scope == nil || scope.ScopeKind == core.ReportScopeKindLocal {
		return "local discovery"
	}

	return describeRemoteScope("remote discovery", scope)
}

func describeAuditScope(scope *core.ReportScope) string {
	if scope == nil || scope.ScopeKind == core.ReportScopeKindLocal {
		return "local audit"
	}

	return describeRemoteScope("remote audit", scope)
}

func describeRemoteScope(prefix string, scope *core.ReportScope) string {
	switch scope.InputKind {
	case core.ReportInputKindCIDR:
		if scope.CIDR != "" {
			return fmt.Sprintf("%s within CIDR %s%s", prefix, scope.CIDR, portsSuffix(scope.Ports))
		}
	case core.ReportInputKindTargetsFile:
		if scope.TargetsFile != "" {
			return fmt.Sprintf("%s from targets file %s%s", prefix, scope.TargetsFile, portsSuffix(scope.Ports))
		}
	case core.ReportInputKindInventoryFile:
		if scope.InventoryFile != "" {
			return fmt.Sprintf("%s from inventory file %s%s%s", prefix, scope.InventoryFile, adapterSuffix(scope.Adapter), portsSuffix(scope.Ports))
		}
	}

	return prefix
}

func adapterSuffix(adapter core.InventoryAdapter) string {
	if adapter == "" {
		return ""
	}

	return " via " + string(adapter) + " adapter"
}

func portsSuffix(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}

	return " over ports " + strings.Join(values, ",")
}
