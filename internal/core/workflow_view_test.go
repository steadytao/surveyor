// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"slices"
	"testing"
)

func TestMatchesWorkflowFilters(t *testing.T) {
	t.Parallel()

	inventory := &InventoryAnnotation{
		Owner:       "Payments",
		Environment: "Prod",
		Tags:        []string{"external", "critical"},
		Provenance: []InventoryProvenance{
			{
				SourceKind:   InventorySourceKindInventoryFile,
				SourceFormat: InventorySourceFormatCSV,
				SourceName:   "exports/cmdb.csv",
			},
		},
	}

	filters := []WorkflowFilter{
		{
			Field:  WorkflowFilterFieldOwner,
			Values: []string{"payments"},
		},
		{
			Field:  WorkflowFilterFieldEnvironment,
			Values: []string{"prod"},
		},
		{
			Field:  WorkflowFilterFieldTag,
			Values: []string{"external"},
		},
		{
			Field:  WorkflowFilterFieldSource,
			Values: []string{"exports/cmdb.csv"},
		},
	}

	if !MatchesWorkflowFilters(inventory, filters) {
		t.Fatal("MatchesWorkflowFilters() = false, want true")
	}

	filters[1].Values = []string{"dev"}
	if MatchesWorkflowFilters(inventory, filters) {
		t.Fatal("MatchesWorkflowFilters() = true, want false for mismatched environment")
	}
}

func TestWorkflowGroupKeys(t *testing.T) {
	t.Parallel()

	inventory := &InventoryAnnotation{
		Owner:       "payments",
		Environment: "prod",
		Provenance: []InventoryProvenance{
			{
				SourceName: "exports/cmdb.csv",
			},
			{
				SourceFormat: InventorySourceFormatCSV,
			},
			{
				SourceName: "exports/cmdb.csv",
			},
		},
	}

	if got, want := WorkflowGroupKeys(WorkflowGroupByOwner, inventory), []string{"payments"}; !slices.Equal(got, want) {
		t.Fatalf("WorkflowGroupKeys(owner) = %v, want %v", got, want)
	}
	if got, want := WorkflowGroupKeys(WorkflowGroupByEnvironment, inventory), []string{"prod"}; !slices.Equal(got, want) {
		t.Fatalf("WorkflowGroupKeys(environment) = %v, want %v", got, want)
	}
	if got, want := WorkflowGroupKeys(WorkflowGroupBySource, inventory), []string{"csv", "exports/cmdb.csv"}; !slices.Equal(got, want) {
		t.Fatalf("WorkflowGroupKeys(source) = %v, want %v", got, want)
	}
	if got, want := WorkflowGroupKeys(WorkflowGroupByOwner, nil), []string{"unknown"}; !slices.Equal(got, want) {
		t.Fatalf("WorkflowGroupKeys(owner, nil) = %v, want %v", got, want)
	}
}
