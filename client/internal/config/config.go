package config

import "time"

type Config struct {
	Addr       string
	Timeout    time.Duration
	UseTLS     bool
	MaxRetries int
}

func DefaultConfig() Config {
	return Config{
		Addr:       "localhost:5000",
		Timeout:    5 * time.Second,
		UseTLS:     false,
		MaxRetries: 3,
	}
}
