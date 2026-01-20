package httpclient

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"time"
	"yqhunter/internal/config"
)

// Client 统一的HTTP客户端结构体
type Client struct {
	*http.Client
}

// New 创建新的HTTP客户端
func New(cfg *config.Config) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.General.SkipSSLVerify,
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		DisableKeepAlives:     false,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// 配置代理
	if cfg.General.Proxy != "" {
		parsedURL, err := url.Parse(cfg.General.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(parsedURL)
		}
	}

	return &Client{
		Client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.General.Timeout) * time.Second,
		},
	}
}

// NewWithTimeout 创建带有自定义超时的HTTP客户端
func NewWithTimeout(cfg *config.Config, timeout time.Duration) *Client {
	client := New(cfg)
	maxTimeout := 5 * time.Minute
	if timeout > maxTimeout {
		timeout = maxTimeout
		log.Printf("[Security] Timeout exceeds maximum allowed (%v), using max timeout", maxTimeout)
	}
	client.Timeout = timeout
	return client
}

const maxAllowedTimeout = 5 * time.Minute

// NewWithNoTimeout 创建不设置超时的HTTP客户端（已废弃，不推荐使用）
// 警告：此函数可能造成资源耗尽，建议使用 NewWithTimeout
// 如果必须使用，调用者应确保有其他机制限制请求时间
func NewWithNoTimeout(cfg *config.Config) *Client {
	log.Println("[Security] WARNING: NewWithNoTimeout creates a client without timeout limit")
	log.Println("[Security] This may cause resource exhaustion. Consider using NewWithTimeout instead.")
	client := New(cfg)
	client.Timeout = 0
	return client
}

// NewWithDefaultTimeout 使用配置中的超时设置
func NewWithDefaultTimeout(cfg *config.Config) *Client {
	return New(cfg)
}
