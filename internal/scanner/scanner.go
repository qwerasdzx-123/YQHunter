package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"yqhunter/internal/config"
	"yqhunter/internal/httpclient"
)

type Vulnerability struct {
	Type        string
	URL         string
	Payload     string
	Severity    string
	Description string
	Proof       string
}

type ScanResult struct {
	Target       string
	StartTime    time.Time
	EndTime      time.Time
	SSRFResults  []Vulnerability
	CORSResults  []Vulnerability
	DirResults   []DirResult
	Fingerprints []Fingerprint
	APIEndpoints []APIEndpoint
}

type DirResult struct {
	FullURL    string
	Path       string
	StatusCode int
	Size       int64
}

type Fingerprint struct {
	Name    string
	Version string
	Source  string
}

type APIEndpoint struct {
	URL        string
	Method     string
	Parameters []string
}

func createHTTPClient(cfg *config.Config) *http.Client {
	// 使用统一的HTTP客户端管理包
	return httpclient.New(cfg).Client
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "broken pipe") {
		return true
	}

	return false
}

func isRetryableStatusCode(statusCode int) bool {
	if statusCode >= 500 && statusCode <= 599 {
		return true
	}
	return false
}

func doRequestWithRetry(client *http.Client, req *http.Request, maxRetries int) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err := client.Do(req)

		if err != nil {
			lastErr = err
			if !isRetryableError(err) {
				return nil, err
			}
		} else {
			if !isRetryableStatusCode(resp.StatusCode) {
				return resp, nil
			}

			if resp != nil {
				resp.Body.Close()
			}
		}

		if attempt < maxRetries {
			backoff := time.Duration(attempt*attempt) * time.Second
			time.Sleep(backoff)

			if req.Body != nil {
				if req.GetBody != nil {
					newBody, err := req.GetBody()
					if err == nil {
						req.Body = newBody
					} else {
						return nil, err
					}
				} else {
					return nil, fmt.Errorf("request body cannot be retried: GetBody is nil")
				}
			}
		}
	}

	return nil, lastErr
}

func RunScan(target string, cfg *config.Config) *ScanResult {
	result := &ScanResult{
		Target:    target,
		StartTime: time.Now(),
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, cfg.General.Concurrency)

	if cfg.Scanner.EnableSSRF {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			result.SSRFResults = ScanSSRF(target, cfg)
		}()
	}

	if cfg.Scanner.EnableCORS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			result.CORSResults = ScanCORS(target, cfg)
		}()
	}

	if cfg.Scanner.EnableDirScan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			result.DirResults = ScanDirectories(target, cfg)
		}()
	}

	if cfg.Scanner.EnableFingerprint {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			result.Fingerprints = DetectFingerprints(target, cfg)
		}()
	}

	if cfg.Scanner.EnableAPI {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			result.APIEndpoints = DiscoverAPIEndpoints(target, cfg)
		}()
	}

	wg.Wait()
	result.EndTime = time.Now()

	return result
}

// SSRFTest 定义SSRF测试用例
type SSRFTest struct {
	Method    string
	ParamName string
	Payload   string
	Headers   map[string]string
	Body      string
	Severity  string
}

func ScanSSRF(target string, cfg *config.Config) []Vulnerability {
	vulns := make([]Vulnerability, 0)

	client := createHTTPClient(cfg)

	// 测试参数名列表
	paramNames := []string{"url", "uri", "path", "endpoint", "target", "redirect", "forward", "proxy"}

	// 生成测试用例
	tests := make([]SSRFTest, 0)
	for _, payload := range cfg.Scanner.SSRFPayloads {
		for _, paramName := range paramNames {
			// GET请求测试
			tests = append(tests, SSRFTest{
				Method:    "GET",
				ParamName: paramName,
				Payload:   payload,
				Headers:   map[string]string{},
				Severity:  "高",
			})

			// POST表单测试
			tests = append(tests, SSRFTest{
				Method:    "POST",
				ParamName: paramName,
				Payload:   payload,
				Headers: map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				},
				Body:     paramName + "=" + url.QueryEscape(payload),
				Severity: "高",
			})

			// JSON格式测试
			tests = append(tests, SSRFTest{
				Method:    "POST",
				ParamName: paramName,
				Payload:   payload,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body:     fmt.Sprintf(`{"%s":"%s"}`, paramName, payload),
				Severity: "高",
			})
		}
	}

	// 执行所有测试用例
	for _, test := range tests {
		var testURL string
		var req *http.Request
		var err error

		if test.Method == "GET" {
			// GET请求：将参数加到URL中
			testURL = fmt.Sprintf("%s?%s=%s", target, test.ParamName, url.QueryEscape(test.Payload))
			req, err = http.NewRequest("GET", testURL, nil)
		} else {
			// POST请求：将参数放在请求体中
			testURL = target
			req, err = http.NewRequest("POST", testURL, strings.NewReader(test.Body))
		}

		if err != nil {
			continue
		}

		// 设置请求头
		req.Header.Set("User-Agent", cfg.General.UserAgent)
		for key, value := range test.Headers {
			req.Header.Set(key, value)
		}

		// 发送请求
		resp, err := doRequestWithRetry(client, req, cfg.General.MaxRetries)
		if err != nil {
			continue
		}

		// 读取响应
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// 检测SSRF漏洞
		if detectSSRFInResponse(bodyStr, test.Payload) {
			vulns = append(vulns, Vulnerability{
				Type:        "SSRF",
				URL:         testURL,
				Payload:     test.Payload,
				Severity:    test.Severity,
				Description: fmt.Sprintf("检测到服务器端请求伪造漏洞，通过%s请求的%s参数", test.Method, test.ParamName),
				Proof:       fmt.Sprintf("内部地址或特征在响应中暴露: %s", extractSSRFProof(bodyStr)),
			})
		}
	}

	return vulns
}

// detectSSRFInResponse 检测响应中的SSRF漏洞
func detectSSRFInResponse(body, payload string) bool {
	// 检测内部地址
	internalIndicators := []string{
		"127.0.0.1",
		"localhost",
		"169.254.169.254",
		"meta-data",
		"aws",
		"ec2",
		"google",
		"gcp",
		"azure",
	}

	for _, indicator := range internalIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	// 检测常见内部服务响应特征
	responseIndicators := []string{
		"Connection refused",
		"No route to host",
		"Internal Server Error",
		"nginx/",
		"apache/",
		"Microsoft-IIS",
	}

	for _, indicator := range responseIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}

// extractSSRFProof 提取SSRF漏洞的证明信息
func extractSSRFProof(body string) string {
	internalIndicators := []string{
		"127.0.0.1",
		"localhost",
		"169.254.169.254",
		"meta-data",
		"aws",
		"ec2",
		"google",
		"gcp",
		"azure",
	}

	for _, indicator := range internalIndicators {
		if strings.Contains(body, indicator) {
			return indicator
		}
	}

	return "响应包含内部服务特征"
}

// CORSTest 定义CORS测试用例
type CORSTest struct {
	Method              string
	URL                 string
	Origin              string
	ACRequestMethod     string
	ACRequestHeaders    []string
	WithCredentials     bool
	Severity            string
}

func ScanCORS(target string, cfg *config.Config) []Vulnerability {
	vulns := make([]Vulnerability, 0)

	client := createHTTPClient(cfg)

	// 测试用例
	tests := []CORSTest{
		// OPTIONS请求测试
		{
			Method:              "OPTIONS",
			URL:                 target,
			Origin:              "http://evil.com",
			ACRequestMethod:     "GET",
			ACRequestHeaders:    []string{},
			WithCredentials:     false,
			Severity:            "高",
		},
		{
			Method:              "OPTIONS",
			URL:                 target,
			Origin:              "http://attacker.com",
			ACRequestMethod:     "POST",
			ACRequestHeaders:    []string{"Content-Type"}, 
			WithCredentials:     true,
			Severity:            "高",
		},
		{
			Method:              "OPTIONS",
			URL:                 target,
			Origin:              "http://localhost:3000",
			ACRequestMethod:     "PUT",
			ACRequestHeaders:    []string{},
			WithCredentials:     false,
			Severity:            "高",
		},
		// 实际GET请求测试
		{
			Method:              "GET",
			URL:                 target,
			Origin:              "http://evil.com",
			ACRequestMethod:     "",
			ACRequestHeaders:    []string{},
			WithCredentials:     true,
			Severity:            "高",
		},
		// 实际POST请求测试
		{
			Method:              "POST",
			URL:                 target,
			Origin:              "http://attacker.com",
			ACRequestMethod:     "",
			ACRequestHeaders:    []string{"Content-Type"},
			WithCredentials:     true,
			Severity:            "高",
		},
	}

	// 执行所有测试用例
	for _, test := range tests {
		var bodyReader io.Reader
		req, err := http.NewRequest(test.Method, test.URL, bodyReader)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", cfg.General.UserAgent)
		req.Header.Set("Origin", test.Origin)

		if test.Method == "OPTIONS" {
			if test.ACRequestMethod != "" {
				req.Header.Set("Access-Control-Request-Method", test.ACRequestMethod)
			}

			for _, header := range test.ACRequestHeaders {
				req.Header.Add("Access-Control-Request-Headers", header)
			}
		}

		// 发送请求
		resp, err := doRequestWithRetry(client, req, cfg.General.MaxRetries)
		if err != nil {
			continue
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		resp.Body.Close()

		// 检查CORS配置
		if acao == "*" {
			if acac == "true" {
				vulns = append(vulns, Vulnerability{
					Type:        "CORS",
					URL:         test.URL,
					Payload:     test.Origin,
					Severity:    "高",
					Description: "检测到 CORS 配置错误：允许任意来源并携带凭据",
					Proof:       fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: true", acao),
				})
			} else {
				vulns = append(vulns, Vulnerability{
					Type:        "CORS",
					URL:         test.URL,
					Payload:     test.Origin,
					Severity:    "中",
					Description: "检测到 CORS 配置错误：允许任意来源",
					Proof:       fmt.Sprintf("Access-Control-Allow-Origin: %s", acao),
				})
			}
		}

		if acao == test.Origin {
			if acac == "true" && test.WithCredentials {
				vulns = append(vulns, Vulnerability{
					Type:        "CORS",
					URL:         test.URL,
					Payload:     test.Origin,
					Severity:    "高",
					Description: "检测到 CORS 配置错误：允许特定来源并携带凭据",
					Proof:       fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: true", acao),
				})
			}
		}
	}

	return vulns
}

type dirScanTask struct {
	path    string
	fullURL string
}

func buildDirScanURL(targetURL *url.URL, dir string) string {
	reference, err := url.Parse(dir)
	if err != nil {
		return targetURL.String() + "/" + dir
	}
	return targetURL.ResolveReference(reference).String()
}

func isNotFoundStatus(statusCode int) bool {
	return statusCode == 404
}

func ScanDirectories(target string, cfg *config.Config) []DirResult {
	results := make([]DirResult, 0)
	resultsChan := make(chan DirResult, 100)

	client := createHTTPClient(cfg)

	wordlist := []string{
		"admin", "api", "backup", "config", "db", "debug", "docs", "files",
		"images", "includes", "js", "login", "logs", "media", "uploads", "test",
		"tmp", "vendor", "web", "www", ".git", ".env", "phpmyadmin", "wp-admin",
	}

	if cfg.Scanner.DictFile != "" {
		loadedWordlist, err := loadWordlist(cfg.Scanner.DictFile)
		if err == nil && len(loadedWordlist) > 0 {
			wordlist = loadedWordlist
			fmt.Printf("使用字典文件: %s (%d 条记录)\n", cfg.Scanner.DictFile, len(wordlist))
		} else {
			fmt.Printf("加载字典文件失败: %v，尝试从 dictionaries 目录加载默认字典\n", err)
			defaultDict := "dictionaries/common.txt"
			loadedWordlist, err := loadWordlist(defaultDict)
			if err == nil && len(loadedWordlist) > 0 {
				wordlist = loadedWordlist
				fmt.Printf("使用默认字典文件: %s (%d 条记录)\n", defaultDict, len(wordlist))
			} else {
				fmt.Printf("加载默认字典文件失败: %v，使用内置小字典\n", err)
			}
		}
	} else {
		defaultDict := "dictionaries/common.txt"
		loadedWordlist, err := loadWordlist(defaultDict)
		if err == nil && len(loadedWordlist) > 0 {
			wordlist = loadedWordlist
			fmt.Printf("使用默认字典文件: %s (%d 条记录)\n", defaultDict, len(wordlist))
		} else {
			fmt.Printf("加载默认字典文件失败: %v，使用内置小字典\n", err)
		}
	}

	concurrency := cfg.General.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		fmt.Printf("解析目标 URL 失败: %v\n", err)
		return results
	}

	taskChan := make(chan dirScanTask, 100)
	var wg sync.WaitGroup
	total := len(wordlist)
	scanned := 0
	var mu sync.Mutex

	fmt.Printf("开始目录扫描，并发数: %d\n", concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				req, err := http.NewRequest("HEAD", task.fullURL, nil)
				if err != nil {
					mu.Lock()
					scanned++
					if scanned%50 == 0 || scanned == total {
						fmt.Printf("进度: %d/%d (%.1f%%)\n", scanned, total, float64(scanned)*100/float64(total))
					}
					mu.Unlock()
					continue
				}

				req.Header.Set("User-Agent", cfg.General.UserAgent)

				resp, err := doRequestWithRetry(client, req, cfg.General.MaxRetries)
				if err != nil {
					mu.Lock()
					scanned++
					if scanned%50 == 0 || scanned == total {
						fmt.Printf("进度: %d/%d (%.1f%%)\n", scanned, total, float64(scanned)*100/float64(total))
					}
					mu.Unlock()
					continue
				}
				resp.Body.Close()

				if !isNotFoundStatus(resp.StatusCode) {
					resultsChan <- DirResult{
						FullURL:    task.fullURL,
						Path:       task.path,
						StatusCode: resp.StatusCode,
						Size:       resp.ContentLength,
					}
				}

				mu.Lock()
				scanned++
				if scanned%50 == 0 || scanned == total {
					fmt.Printf("进度: %d/%d (%.1f%%)\n", scanned, total, float64(scanned)*100/float64(total))
				}
				mu.Unlock()
			}
		}()
	}

	go func() {
		for _, dir := range wordlist {
			taskChan <- dirScanTask{
				path:    dir,
				fullURL: buildDirScanURL(targetURL, dir),
			}
		}
		close(taskChan)
	}()

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	fmt.Printf("目录扫描完成。发现 %d 个路径\n", len(results))
	return results
}

func loadWordlist(filepath string) ([]string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	wordlist := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			wordlist = append(wordlist, line)
		}
	}

	return wordlist, nil
}

func DetectFingerprints(target string, cfg *config.Config) []Fingerprint {
	fingerprints := make([]Fingerprint, 0)

	client := createHTTPClient(cfg)

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return fingerprints
	}

	req.Header.Set("User-Agent", cfg.General.UserAgent)

	resp, err := doRequestWithRetry(client, req, cfg.General.MaxRetries)
	if err != nil {
		return fingerprints
	}
	defer resp.Body.Close()

	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		fingerprints = append(fingerprints, Fingerprint{
			Name:    "服务器",
			Version: serverHeader,
			Source:  "响应头",
		})
	}

	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		fingerprints = append(fingerprints, Fingerprint{
			Name:    "技术栈",
			Version: xPoweredBy,
			Source:  "响应头",
		})
	}

	return fingerprints
}

func DiscoverAPIEndpoints(target string, cfg *config.Config) []APIEndpoint {
	endpoints := make([]APIEndpoint, 0)

	apiPaths := []string{
		"/api/v1", "/api/v2", "/api", "/rest", "/graphql", "/swagger", "/api-docs",
	}

	client := createHTTPClient(cfg)

	for _, path := range apiPaths {
		testURL := target + path

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", cfg.General.UserAgent)

		resp, err := doRequestWithRetry(client, req, cfg.General.MaxRetries)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			endpoints = append(endpoints, APIEndpoint{
				URL:    testURL,
				Method: "GET",
			})
		}
	}

	return endpoints
}
