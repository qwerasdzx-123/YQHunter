package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	General GeneralConfig `mapstructure:"general"`
	Scanner ScannerConfig `mapstructure:"scanner"`
	Spider  SpiderConfig  `mapstructure:"spider"`
	Report  ReportConfig  `mapstructure:"report"`
	Auth    AuthConfig    `mapstructure:"auth"`
}

type GeneralConfig struct {
	Timeout       int    `mapstructure:"timeout"`
	UserAgent     string `mapstructure:"user_agent"`
	MaxRetries    int    `mapstructure:"max_retries"`
	Proxy         string `mapstructure:"proxy"`
	Concurrency   int    `mapstructure:"concurrency"`
	SkipSSLVerify bool   `mapstructure:"skip_ssl_verify"`
}

type ScannerConfig struct {
	EnableXSS        bool     `mapstructure:"enable_xss"`
	EnableSSRF       bool     `mapstructure:"enable_ssrf"`
	EnableCORS       bool     `mapstructure:"enable_cors"`
	EnableDirScan    bool     `mapstructure:"enable_dir_scan"`
	EnableFingerprint bool    `mapstructure:"enable_fingerprint"`
	EnableAPI        bool     `mapstructure:"enable_api"`
	XSSPayloads      []string `mapstructure:"xss_payloads"`
	SSRFPayloads     []string `mapstructure:"ssrf_payloads"`
	DirWordlist      string   `mapstructure:"dir_wordlist"`
	DictFile         string   `mapstructure:"dict_file"`
	FingerprintFile  string   `mapstructure:"fingerprint_file"`
}

type SpiderConfig struct {
	MaxDepth      int      `mapstructure:"max_depth"`
	MaxPages      int      `mapstructure:"max_pages"`
	FollowLinks   bool     `mapstructure:"follow_links"`
	AllowDomains  []string `mapstructure:"allow_domains"`
	ExcludePaths  []string `mapstructure:"exclude_paths"`
	Proxy         string   `mapstructure:"proxy"`
}

type ReportConfig struct {
	OutputDir     string `mapstructure:"output_dir"`
	Format        string `mapstructure:"format"`
	IncludeDetails bool   `mapstructure:"include_details"`
}

type AuthConfig struct {
	LicenseKey string `mapstructure:"license_key"`
	Enabled    bool   `mapstructure:"enabled"`
}

func LoadConfig(configFile string) *Config {
	cfg := &Config{}
	
	setDefaults(cfg)
	
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.yqhunter")
		viper.AddConfigPath("/etc/yqhunter")
	}
	
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("使用配置文件:", viper.ConfigFileUsed())
		if err := viper.Unmarshal(cfg); err != nil {
			fmt.Printf("解析配置文件错误: %v\n", err)
		}
	} else {
		fmt.Println("使用默认配置")
	}
	
	return cfg
}

func setDefaults(cfg *Config) {
	cfg.General = GeneralConfig{
		Timeout:     30,
		UserAgent:   "YQHunter/1.0",
		MaxRetries:  3,
		Concurrency: 10,
	}
	
	cfg.Scanner = ScannerConfig{
		EnableXSS:         true,
		EnableSSRF:        true,
		EnableCORS:        true,
		EnableDirScan:     true,
		EnableFingerprint: true,
		EnableAPI:         true,
		XSSPayloads: []string{
			"<script>alert('XSS')</script>",
			"<img src=x onerror=alert('XSS')>",
			"javascript:alert('XSS')",
			"<svg onload=alert('XSS')>",
		},
		SSRFPayloads: []string{
			"http://127.0.0.1:80",
			"http://localhost:8080",
			"http://169.254.169.254/latest/meta-data/",
			"http://[::1]",
			"file:///etc/passwd",
		},
		DirWordlist:     "wordlists/directories.txt",
		FingerprintFile: "fingerprints.yaml",
	}
	
	cfg.Spider = SpiderConfig{
		MaxDepth:    3,
		MaxPages:    1000,
		FollowLinks: true,
		Proxy:       "",
	}
	
	cfg.Report = ReportConfig{
		OutputDir:     "reports",
		Format:        "html",
		IncludeDetails: true,
	}
}

func SaveDefaultConfig(filename string) error {
	cfg := &Config{}
	setDefaults(cfg)
	
	viper.Set("general", cfg.General)
	viper.Set("scanner", cfg.Scanner)
	viper.Set("spider", cfg.Spider)
	viper.Set("report", cfg.Report)
	
	return viper.SafeWriteConfigAs(filename)
}

func EnsureWordlistsExist() error {
	wordlistsDir := "wordlists"
	if _, err := os.Stat(wordlistsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(wordlistsDir, 0755); err != nil {
			return fmt.Errorf("创建字典目录失败: %w", err)
		}
	}
	
	defaultWordlists := map[string][]string{
		"directories.txt": {
			"admin", "api", "backup", "config", "db", "debug", "docs", "files",
			"images", "includes", "js", "login", "logs", "media", "uploads", "test",
			"tmp", "vendor", "web", "www", ".git", ".env", "phpmyadmin", "wp-admin",
		},
		"subdomains.txt": {
			"www", "mail", "ftp", "admin", "blog", "dev", "staging", "test",
			"api", "app", "portal", "secure", "vpn", "cdn", "static", "assets",
		},
	}
	
	for filename, content := range defaultWordlists {
		filepath := wordlistsDir + "/" + filename
		if _, err := os.Stat(filepath); os.IsNotExist(err) {
			file, err := os.Create(filepath)
			if err != nil {
				return fmt.Errorf("创建字典文件 %s 失败: %w", filename, err)
			}
			defer file.Close()
			
			for _, line := range content {
				if _, err := file.WriteString(line + "\n"); err != nil {
					return fmt.Errorf("写入字典文件 %s 失败: %w", filename, err)
				}
			}
		}
	}
	
	return nil
}
