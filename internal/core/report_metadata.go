// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package core

// CurrentSchemaVersion is the current baseline-compatible report schema version.
const CurrentSchemaVersion = "1.0"

// CurrentToolVersion records the emitting Surveyor build version. It defaults to
// "dev" for ordinary builds and tests; release builds can override it later.
var CurrentToolVersion = "dev"

// ReportKind records the semantic top-level report type.
type ReportKind string

const (
	ReportKindTLSScan        ReportKind = "tls_scan"
	ReportKindDiscovery      ReportKind = "discovery"
	ReportKindAudit          ReportKind = "audit"
	ReportKindDiff           ReportKind = "diff"
	ReportKindPrioritization ReportKind = "prioritization"
)

// ReportScopeKind records the high-level scope a report covers.
type ReportScopeKind string

const (
	ReportScopeKindExplicit ReportScopeKind = "explicit"
	ReportScopeKindLocal    ReportScopeKind = "local"
	ReportScopeKindRemote   ReportScopeKind = "remote"
)

// ReportInputKind records how the current report scope or target set was
// declared.
type ReportInputKind string

const (
	ReportInputKindConfig        ReportInputKind = "config"
	ReportInputKindTargets       ReportInputKind = "targets"
	ReportInputKindCIDR          ReportInputKind = "cidr"
	ReportInputKindTargetsFile   ReportInputKind = "targets_file"
	ReportInputKindInventoryFile ReportInputKind = "inventory_file"
)

// ReportMetadata records baseline-compatible top-level report metadata.
type ReportMetadata struct {
	SchemaVersion    string          `json:"schema_version"`
	ToolVersion      string          `json:"tool_version"`
	ReportKind       ReportKind      `json:"report_kind"`
	ScopeKind        ReportScopeKind `json:"scope_kind"`
	ScopeDescription string          `json:"scope_description,omitempty"`
}

// NewReportMetadata assembles the current top-level report metadata.
func NewReportMetadata(reportKind ReportKind, scopeKind ReportScopeKind, scopeDescription string) ReportMetadata {
	return ReportMetadata{
		SchemaVersion:    CurrentSchemaVersion,
		ToolVersion:      CurrentToolVersion,
		ReportKind:       reportKind,
		ScopeKind:        scopeKind,
		ScopeDescription: scopeDescription,
	}
}
