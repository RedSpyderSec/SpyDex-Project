package config

import (
	"flag"
)

// Config holds all the configuration flags and options for spydex.
type Config struct {
	ProxyPort string
	DBPath    string
	CACert    string
	CAKey     string
}

// LoadConfig parses command-line flags and returns a populated Config struct.
func LoadConfig() *Config {
	proxyPort := flag.String("port", "8080", "Proxy port to listen on")
	dbPath := flag.String("db", "spydex.db", "SQLite database path for history persistence")
	caCert := flag.String("cacert", "ca.crt", "Path to CA certificate file")
	caKey := flag.String("cakey", "ca.key", "Path to CA private key file")

	flag.Parse()

	return &Config{
		ProxyPort: *proxyPort,
		DBPath:    *dbPath,
		CACert:    *caCert,
		CAKey:     *caKey,
	}
}
