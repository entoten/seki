package config

// Load reads configuration from a YAML file and environment variables.
// TODO: Implement YAML parsing and env var overrides.
func Load(path string) (*Config, error) {
	return &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Database: DatabaseConfig{
			Driver: "postgres",
		},
	}, nil
}
