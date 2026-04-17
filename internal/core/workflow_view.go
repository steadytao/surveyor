package core

import (
	"slices"
	"strings"
)

// MatchesWorkflowFilters reports whether one inventory annotation satisfies the
// supplied workflow filters. Multiple filters are combined with logical AND;
// multiple values within one filter are combined with logical OR.
func MatchesWorkflowFilters(inventory *InventoryAnnotation, filters []WorkflowFilter) bool {
	if len(filters) == 0 {
		return true
	}
	if inventory == nil {
		return false
	}

	for _, filter := range filters {
		if !matchesWorkflowFilter(inventory, filter) {
			return false
		}
	}

	return true
}

// WorkflowGroupKeys returns the stable grouping keys for one inventory
// annotation and one supported grouping dimension.
func WorkflowGroupKeys(groupBy WorkflowGroupBy, inventory *InventoryAnnotation) []string {
	switch groupBy {
	case WorkflowGroupByOwner:
		if inventory == nil || strings.TrimSpace(inventory.Owner) == "" {
			return []string{"unknown"}
		}
		return []string{strings.TrimSpace(inventory.Owner)}
	case WorkflowGroupByEnvironment:
		if inventory == nil || strings.TrimSpace(inventory.Environment) == "" {
			return []string{"unknown"}
		}
		return []string{strings.TrimSpace(inventory.Environment)}
	case WorkflowGroupBySource:
		return workflowSourceKeys(inventory)
	default:
		return nil
	}
}

func matchesWorkflowFilter(inventory *InventoryAnnotation, filter WorkflowFilter) bool {
	if len(filter.Values) == 0 {
		return true
	}

	switch filter.Field {
	case WorkflowFilterFieldOwner:
		return matchesWorkflowStringValue(inventory.Owner, filter.Values)
	case WorkflowFilterFieldEnvironment:
		return matchesWorkflowStringValue(inventory.Environment, filter.Values)
	case WorkflowFilterFieldTag:
		return matchesWorkflowTagValues(inventory.Tags, filter.Values)
	case WorkflowFilterFieldSource:
		sourceKeys := workflowSourceKeys(inventory)
		for _, key := range sourceKeys {
			if matchesWorkflowStringValue(key, filter.Values) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func matchesWorkflowStringValue(value string, expected []string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}

	for _, candidate := range expected {
		if strings.EqualFold(trimmed, strings.TrimSpace(candidate)) {
			return true
		}
	}

	return false
}

func matchesWorkflowTagValues(tags []string, expected []string) bool {
	if len(tags) == 0 {
		return false
	}

	for _, tag := range tags {
		if matchesWorkflowStringValue(tag, expected) {
			return true
		}
	}

	return false
}

func workflowSourceKeys(inventory *InventoryAnnotation) []string {
	if inventory == nil || len(inventory.Provenance) == 0 {
		return []string{"unknown"}
	}

	seen := map[string]struct{}{}
	keys := make([]string, 0, len(inventory.Provenance))
	for _, provenance := range inventory.Provenance {
		key := workflowSourceKey(provenance)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}

	slices.Sort(keys)
	return keys
}

func workflowSourceKey(provenance InventoryProvenance) string {
	if strings.TrimSpace(provenance.SourceName) != "" {
		return strings.TrimSpace(provenance.SourceName)
	}
	if strings.TrimSpace(string(provenance.SourceFormat)) != "" {
		return strings.TrimSpace(string(provenance.SourceFormat))
	}
	if strings.TrimSpace(string(provenance.SourceKind)) != "" {
		return strings.TrimSpace(string(provenance.SourceKind))
	}
	return "unknown"
}
