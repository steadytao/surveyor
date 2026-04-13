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
	host := strings.TrimSpace(target.Host)
	name := strings.TrimSpace(target.Name)
	pathPrefix := fmt.Sprintf("targets[%d]", index)

	if host == "" {
		return Target{}, fmt.Errorf("%s.host must not be empty", pathPrefix)
	}

	if target.Port < 1 || target.Port > 65535 {
		return Target{}, fmt.Errorf("%s.port must be between 1 and 65535", pathPrefix)
	}

	if target.Name != "" && name == "" {
		return Target{}, fmt.Errorf("%s.name must not be blank", pathPrefix)
	}

	tags := normalizeTags(target.Tags)

	return Target{
		Name: name,
		Host: host,
		Port: target.Port,
		Tags: tags,
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
