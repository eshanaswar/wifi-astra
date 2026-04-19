package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	ModDir    string            `mapstructure:"mod_dir"`
	SessionDir string           `mapstructure:"session_dir"`
	Verbose   bool              `mapstructure:"verbose"`
	ToolPaths map[string]string `mapstructure:"tool_paths"`
}

var GlobalConfig *Config

// LoadConfig initializes the configuration from files, environment, and flags.
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()

	// Default values
	v.SetDefault("mod_dir", "./modules")
	v.SetDefault("session_dir", "./sessions")
	v.SetDefault("verbose", false)
	v.SetDefault("tool_paths", map[string]string{
		"airmon-ng":   "airmon-ng",
		"airodump-ng": "airodump-ng",
		"aireplay-ng": "aireplay-ng",
		"hcxdumptool": "hcxdumptool",
		"nmap":        "nmap",
		"bettercap":   "bettercap",
		"eaphammer":   "eaphammer",
	})

	// Environment variables
	v.SetEnvPrefix("ASTRA")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Config file locations
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("wifi-astra")
		v.SetConfigType("yaml")
		v.AddConfigPath("/etc/")
		v.AddConfigPath("$HOME/.config/")
		v.AddConfigPath(".")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %v", err)
		}
	}

	var c Config
	if err := v.Unmarshal(&c); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	GlobalConfig = &c
	return &c, nil
}

