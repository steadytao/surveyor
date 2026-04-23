// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/steadytao/surveyor/internal/core"
	"github.com/steadytao/surveyor/internal/debugassert"
)

// ReportHeader is the minimum canonical report envelope needed for baseline
// compatibility checks before diffing.
type ReportHeader struct {
	core.ReportMetadata
	GeneratedAt time.Time         `json:"generated_at"`
	Scope       *core.ReportScope `json:"scope,omitempty"`
}

// ReadReportHeader reads and validates the baseline-compatible report envelope
// from disk.
func ReadReportHeader(path string) (ReportHeader, error) {
	// #nosec G304 -- report header paths are explicit operator-provided CLI inputs.
	data, err := os.ReadFile(path)
	if err != nil {
		return ReportHeader{}, fmt.Errorf("read report %q: %w", path, err)
	}

	header, err := ParseReportHeader(data)
	if err != nil {
		return ReportHeader{}, fmt.Errorf("parse report %q: %w", path, err)
	}

	return header, nil
}

// ParseReportHeader decodes and validates the baseline-compatible report
// envelope from canonical Surveyor JSON.
func ParseReportHeader(data []byte) (ReportHeader, error) {
	var header ReportHeader

	if err := json.Unmarshal(data, &header); err != nil {
		return ReportHeader{}, fmt.Errorf("parse report JSON: %w", err)
	}

	if err := validateReportHeader(header); err != nil {
		return ReportHeader{}, err
	}

	assertValidReportHeader(header)
	return header, nil
}

func validateReportHeader(header ReportHeader) error {
	if header.SchemaVersion == "" {
		return fmt.Errorf("report is missing schema_version")
	}
	if header.ToolVersion == "" {
		return fmt.Errorf("report is missing tool_version")
	}
	if header.ReportKind == "" {
		return fmt.Errorf("report is missing report_kind")
	}
	if !isKnownReportKind(header.ReportKind) {
		return fmt.Errorf("unsupported report_kind %q", header.ReportKind)
	}
	if header.ScopeKind == "" {
		return fmt.Errorf("report is missing scope_kind")
	}
	if !isKnownScopeKind(header.ScopeKind) {
		return fmt.Errorf("unsupported scope_kind %q", header.ScopeKind)
	}
	if header.ScopeDescription == "" {
		return fmt.Errorf("report is missing scope_description")
	}
	if header.GeneratedAt.IsZero() {
		return fmt.Errorf("report is missing generated_at")
	}

	switch header.ReportKind {
	case core.ReportKindTLSScan, core.ReportKindDiscovery, core.ReportKindAudit:
		if header.Scope == nil {
			return fmt.Errorf("report is missing scope metadata")
		}
		if err := validateReportScope(header.ScopeKind, header.Scope); err != nil {
			return err
		}
	case core.ReportKindDiff, core.ReportKindPrioritization:
		if header.Scope != nil {
			if err := validateKnownScope(header.Scope.ScopeKind); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateReportScope(scopeKind core.ReportScopeKind, scope *core.ReportScope) error {
	if scope.ScopeKind == "" {
		return fmt.Errorf("report scope is missing scope_kind")
	}
	if scope.ScopeKind != scopeKind {
		return fmt.Errorf("report scope_kind %q does not match scope.scope_kind %q", scopeKind, scope.ScopeKind)
	}
	if err := validateKnownScope(scope.ScopeKind); err != nil {
		return err
	}

	switch scope.ScopeKind {
	case core.ReportScopeKindExplicit:
		return validateExplicitReportScope(scope)
	case core.ReportScopeKindLocal:
		return validateLocalReportScope(scope)
	case core.ReportScopeKindRemote:
		return validateRemoteReportScope(scope)
	}

	return nil
}

func validateExplicitReportScope(scope *core.ReportScope) error {
	if scope.InputKind != core.ReportInputKindConfig && scope.InputKind != core.ReportInputKindTargets {
		return fmt.Errorf("explicit report scope must use input_kind config or targets")
	}
	if hasRemoteScopeFields(scope) {
		return fmt.Errorf("explicit report scope must not include remote scope fields")
	}
	return nil
}

func validateLocalReportScope(scope *core.ReportScope) error {
	if scope.InputKind != "" {
		return fmt.Errorf("local report scope must not include input_kind")
	}
	if hasRemoteScopeFields(scope) {
		return fmt.Errorf("local report scope must not include remote scope fields")
	}
	return nil
}

func validateRemoteReportScope(scope *core.ReportScope) error {
	switch scope.InputKind {
	case core.ReportInputKindCIDR:
		return validateRemoteCIDRReportScope(scope)
	case core.ReportInputKindTargetsFile:
		return validateRemoteTargetsFileReportScope(scope)
	case core.ReportInputKindInventoryFile:
		return validateRemoteInventoryFileReportScope(scope)
	default:
		return fmt.Errorf("remote report scope must use input_kind cidr, targets_file or inventory_file")
	}
}

func validateRemoteCIDRReportScope(scope *core.ReportScope) error {
	if scope.CIDR == "" {
		return fmt.Errorf("remote CIDR scope must include cidr")
	}
	if scope.TargetsFile != "" || scope.InventoryFile != "" || scope.Adapter != "" {
		return fmt.Errorf("remote CIDR scope must not include targets_file, inventory_file or adapter")
	}
	if len(scope.Ports) == 0 {
		return fmt.Errorf("remote CIDR scope must include ports")
	}
	return nil
}

func validateRemoteTargetsFileReportScope(scope *core.ReportScope) error {
	if scope.TargetsFile == "" {
		return fmt.Errorf("remote targets-file scope must include targets_file")
	}
	if scope.CIDR != "" || scope.InventoryFile != "" || scope.Adapter != "" {
		return fmt.Errorf("remote targets-file scope must not include cidr, inventory_file or adapter")
	}
	if len(scope.Ports) == 0 {
		return fmt.Errorf("remote targets-file scope must include ports")
	}
	return nil
}

func validateRemoteInventoryFileReportScope(scope *core.ReportScope) error {
	if scope.InventoryFile == "" {
		return fmt.Errorf("remote inventory-file scope must include inventory_file")
	}
	if scope.CIDR != "" || scope.TargetsFile != "" {
		return fmt.Errorf("remote inventory-file scope must not include cidr or targets_file")
	}
	return nil
}

func hasRemoteScopeFields(scope *core.ReportScope) bool {
	return scope.CIDR != "" || scope.TargetsFile != "" || scope.InventoryFile != "" || scope.Adapter != "" || len(scope.Ports) != 0
}

func isKnownReportKind(kind core.ReportKind) bool {
	switch kind {
	case core.ReportKindTLSScan, core.ReportKindDiscovery, core.ReportKindAudit, core.ReportKindDiff, core.ReportKindPrioritization:
		return true
	default:
		return false
	}
}

func isKnownScopeKind(kind core.ReportScopeKind) bool {
	switch kind {
	case core.ReportScopeKindExplicit, core.ReportScopeKindLocal, core.ReportScopeKindRemote:
		return true
	default:
		return false
	}
}

func validateKnownScope(kind core.ReportScopeKind) error {
	if !isKnownScopeKind(kind) {
		return fmt.Errorf("unsupported scope.scope_kind %q", kind)
	}

	return nil
}

func assertValidReportHeader(header ReportHeader) {
	if !debugassert.Enabled {
		return
	}

	debugassert.That(header.SchemaVersion != "", "report header missing schema version")
	debugassert.That(header.ToolVersion != "", "report header missing tool version")
	debugassert.That(header.ReportKind != "", "report header missing report kind")
	debugassert.That(header.ScopeKind != "", "report header missing scope kind")
	debugassert.That(!header.GeneratedAt.IsZero(), "report header missing generated_at")

	switch header.ReportKind {
	case core.ReportKindTLSScan, core.ReportKindDiscovery, core.ReportKindAudit:
		debugassert.That(header.Scope != nil, "report kind %q must include scope metadata", header.ReportKind)
		debugassert.That(header.Scope.ScopeKind == header.ScopeKind, "report scope kind mismatch")
	}
}
