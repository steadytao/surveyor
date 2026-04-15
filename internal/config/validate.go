package config

import (
	"fmt"
	"strings"
)

func normalize(raw rawConfig) (Config, error) {
	if len(raw.Targets) == 0 {
		return Config{}, fmt.Errorf("config must include at least one target")
	}

	targets := make([]Target, 0, len(raw.Targets))

	for index, target := range raw.Targets {
		normalizedTarget, err := normalizeTarget(target, index)
		if err != nil {
			return Config{}, err
		}

		targets = append(targets, normalizedTarget)
	}

	return Config{
		Targets: targets,
	}, nil
}

func normalizeTarget(target rawTarget, index int) (Target, error) {
	pathPrefix := fmt.Sprintf("targets[%d]", index)

	return normalizeTargetFields(target.Name, target.Host, target.Port, target.Tags, pathPrefix)
}

// ValidateTarget normalises one in-memory target and enforces the same rules
// used for file-backed config input.
func ValidateTarget(target Target) (Target, error) {
	return normalizeTargetFields(target.Name, target.Host, target.Port, target.Tags, "target")
}

func normalizeTargetFields(name string, host string, port int, tags []string, pathPrefix string) (Target, error) {
	trimmedHost := strings.TrimSpace(host)
	trimmedName := strings.TrimSpace(name)

	if trimmedHost == "" {
		return Target{}, fmt.Errorf("%s.host must not be empty", pathPrefix)
	}

	if port < 1 || port > 65535 {
		return Target{}, fmt.Errorf("%s.port must be between 1 and 65535", pathPrefix)
	}

	if name != "" && trimmedName == "" {
		return Target{}, fmt.Errorf("%s.name must not be blank", pathPrefix)
	}

	normalizedTags := normalizeTags(tags)

	return Target{
		Name: trimmedName,
		Host: trimmedHost,
		Port: port,
		Tags: normalizedTags,
	}, nil
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(tags))

	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed == "" {
			continue
		}

		normalized = append(normalized, trimmed)
	}

	if len(normalized) == 0 {
		return nil
	}

	return normalized
}
