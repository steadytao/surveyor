package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Targets []Target `yaml:"targets" json:"targets"`
}

type Target struct {
	Name string   `yaml:"name,omitempty" json:"name,omitempty"`
	Host string   `yaml:"host" json:"host"`
	Port int      `yaml:"port" json:"port"`
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

type rawConfig struct {
	Targets []rawTarget `yaml:"targets"`
}

type rawTarget struct {
	Name string   `yaml:"name"`
	Host string   `yaml:"host"`
	Port int      `yaml:"port"`
	Tags []string `yaml:"tags"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}

	return Parse(data)
}

func Parse(data []byte) (Config, error) {
	var raw rawConfig

	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Config{}, fmt.Errorf("parse YAML config: %w", err)
	}

	return normalize(raw)
}
