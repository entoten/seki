package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the default config file location.
const DefaultPath = "seki.yaml"

// envVarPattern matches ${VAR_NAME} patterns for environment variable expansion.
var envVarPattern = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// Load reads configuration from a YAML file, expands environment variables,
// applies defaults, and validates required fields.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Expand environment variables in the raw YAML before unmarshaling.
	expanded := expandEnvVars(string(data))

	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	applyDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// expandEnvVars replaces all ${VAR} patterns with the corresponding
// environment variable value. Unset variables expand to an empty string.
func expandEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		varName := match[2 : len(match)-1] // strip ${ and }
		return os.Getenv(varName)
	})
}

// applyDefaults sets sensible defaults for fields that were not specified.
func applyDefaults(cfg *Config) {
	if cfg.Server.Address == "" {
		cfg.Server.Address = ":8080"
	}
	if cfg.Signing.Algorithm == "" {
		cfg.Signing.Algorithm = "EdDSA"
	}
	if cfg.Audit.Output == "" {
		cfg.Audit.Output = "stdout"
	}
	// Log defaults.
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = "json"
	}
	// Database connection pool defaults.
	if cfg.Database.MaxOpenConns == 0 {
		cfg.Database.MaxOpenConns = 25
	}
	if cfg.Database.MaxIdleConns == 0 {
		cfg.Database.MaxIdleConns = 5
	}
	if cfg.Database.ConnMaxLifetime == "" {
		cfg.Database.ConnMaxLifetime = "5m"
	}
	if cfg.Database.ConnMaxIdleTime == "" {
		cfg.Database.ConnMaxIdleTime = "1m"
	}
}

// validate checks that required fields are present and values are acceptable.
func validate(cfg *Config) error {
	var errs []string

	if cfg.Server.Issuer == "" {
		errs = append(errs, "server.issuer is required")
	}
	if cfg.Database.Driver == "" {
		errs = append(errs, "database.driver is required")
	}
	if cfg.Database.Driver != "" && cfg.Database.Driver != "postgres" && cfg.Database.Driver != "sqlite" {
		errs = append(errs, fmt.Sprintf("database.driver must be \"postgres\" or \"sqlite\", got %q", cfg.Database.Driver))
	}

	for i, c := range cfg.Clients {
		if c.ID == "" {
			errs = append(errs, fmt.Sprintf("clients[%d].id is required", i))
		}
	}

	for i, o := range cfg.Organizations {
		if o.Slug == "" {
			errs = append(errs, fmt.Sprintf("organizations[%d].slug is required", i))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}
