// Copyright 2026 The Surveyor Authors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkflowContextJSONShape(t *testing.T) {
	t.Parallel()

	context := WorkflowContext{
		GroupBy: WorkflowGroupByOwner,
		Filters: []WorkflowFilter{
			{
				Field:  WorkflowFilterFieldEnvironment,
				Values: []string{"prod"},
			},
			{
				Field:  WorkflowFilterFieldTag,
				Values: []string{"critical", "external"},
			},
		},
	}

	data, err := json.Marshal(context)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)
	wantSubstrings := []string{
		`"group_by":"owner"`,
		`"field":"environment"`,
		`"values":["prod"]`,
		`"field":"tag"`,
		`"values":["critical","external"]`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestGroupedSummaryJSONShape(t *testing.T) {
	t.Parallel()

	summary := GroupedSummary{
		GroupBy: WorkflowGroupByEnvironment,
		Groups: []GroupedSummaryGroup{
			{
				Key:        "prod",
				TotalItems: 3,
				SeverityBreakdown: map[string]int{
					"high": 2,
				},
				CodeBreakdown: map[string]int{
					"classical-certificate-identity": 1,
				},
				DirectionBreakdown: map[string]int{
					"worsened": 1,
				},
				ChangeBreakdown: map[string]int{
					"classification_changed": 1,
				},
			},
		},
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)
	wantSubstrings := []string{
		`"group_by":"environment"`,
		`"key":"prod"`,
		`"total_items":3`,
		`"severity_breakdown":{"high":2}`,
		`"code_breakdown":{"classical-certificate-identity":1}`,
		`"direction_breakdown":{"worsened":1}`,
		`"change_breakdown":{"classification_changed":1}`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestWorkflowFindingJSONShape(t *testing.T) {
	t.Parallel()

	finding := WorkflowFinding{
		Severity:       SeverityMedium,
		Code:           "missing-owner",
		Summary:        "The imported endpoint is missing owner metadata.",
		TargetIdentity: "remote|api.example.com|443|tcp",
		Reason:         "Owner metadata is needed for operational follow-up.",
		Evidence:       []string{"inventory_file=examples/inventory.yaml", "host=api.example.com"},
		Recommendation: "Add owner metadata to the imported inventory source.",
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonText := string(data)
	wantSubstrings := []string{
		`"severity":"medium"`,
		`"code":"missing-owner"`,
		`"summary":"The imported endpoint is missing owner metadata."`,
		`"target_identity":"remote|api.example.com|443|tcp"`,
		`"reason":"Owner metadata is needed for operational follow-up."`,
		`"evidence":["inventory_file=examples/inventory.yaml","host=api.example.com"]`,
		`"recommendation":"Add owner metadata to the imported inventory source."`,
	}

	for _, substring := range wantSubstrings {
		if !strings.Contains(jsonText, substring) {
			t.Fatalf("json output missing substring %q\nfull output: %s", substring, jsonText)
		}
	}
}

func TestCloneWorkflowStructures(t *testing.T) {
	t.Parallel()

	context := &WorkflowContext{
		GroupBy: WorkflowGroupBySource,
		Filters: []WorkflowFilter{
			{
				Field:  WorkflowFilterFieldSource,
				Values: []string{"examples/inventory.yaml"},
			},
		},
	}
	summaries := []GroupedSummary{
		{
			GroupBy: WorkflowGroupByOwner,
			Groups: []GroupedSummaryGroup{
				{
					Key:        "payments",
					TotalItems: 2,
					SeverityBreakdown: map[string]int{
						"high": 1,
					},
					CodeBreakdown: map[string]int{
						"missing-owner": 1,
					},
				},
			},
		},
	}
	findings := []WorkflowFinding{
		{
			Severity: SeverityLow,
			Code:     "inventory-ports-overridden",
			Evidence: []string{"host=api.example.com"},
		},
	}

	clonedContext := CloneWorkflowContext(context)
	clonedSummaries := CloneGroupedSummaries(summaries)
	clonedFindings := CloneWorkflowFindings(findings)

	context.Filters[0].Values[0] = "mutated"
	summaries[0].Groups[0].SeverityBreakdown["high"] = 9
	findings[0].Evidence[0] = "mutated"

	if got, want := clonedContext.Filters[0].Values[0], "examples/inventory.yaml"; got != want {
		t.Fatalf("clonedContext.Filters[0].Values[0] = %q, want %q", got, want)
	}
	if got, want := clonedSummaries[0].Groups[0].SeverityBreakdown["high"], 1; got != want {
		t.Fatalf("clonedSummaries[0].Groups[0].SeverityBreakdown[\"high\"] = %d, want %d", got, want)
	}
	if got, want := clonedFindings[0].Evidence[0], "host=api.example.com"; got != want {
		t.Fatalf("clonedFindings[0].Evidence[0] = %q, want %q", got, want)
	}
}
