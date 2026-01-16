package scanner

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"yqhunter/internal/config"
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
	XSSResults   []Vulnerability
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
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.General.SkipSSLVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   true,
	}

	if cfg.General.Proxy != "" {
		parsedURL, err := url.Parse(cfg.General.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(parsedURL)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.General.Timeout) * time.Second,
	}
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
	var lastResp *http.Response

	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			return resp, nil
		}

		if err != nil {
			lastErr = err
			if !isRetryableError(err) {
				return nil, err
			}
		}

		if resp != nil {
			if lastResp != nil {
				lastResp.Body.Close()
			}
			lastResp = resp

			if !isRetryableStatusCode(resp.StatusCode) {
				return resp, nil
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
					}
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

	if cfg.Scanner.EnableXSS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			result.XSSResults = ScanXSS(target, cfg)
		}()
	}

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

func ScanXSS(target string, cfg *config.Config) []Vulnerability {
	vulns := make([]Vulnerability, 0)

	client := createHTTPClient(cfg)

	fmt.Printf("正在分析目标页面: %s\n", target)

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		fmt.Printf("创建请求失败: %v\n", err)
		return vulns
	}

	req.Header.Set("User-Agent", cfg.General.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return vulns
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应失败: %v\n", err)
		return vulns
	}

	bodyStr := string(body)

	inputNames := extractInputNames(bodyStr)
	fmt.Printf("发现 %d 个输入字段: %v\n", len(inputNames), inputNames)

	if len(inputNames) == 0 {
		inputNames = []string{"name", "search", "query", "q", "input", "text", "message", "comment"}
	}

	for _, payload := range cfg.Scanner.XSSPayloads {
		for _, inputName := range inputNames {
			formData := url.Values{}
			formData.Set(inputName, payload)

			req, err := http.NewRequest("POST", target, bytes.NewBufferString(formData.Encode()))
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", cfg.General.UserAgent)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := doRequestWithRetry(client, req, cfg.General.MaxRetries)
			if err != nil {
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			bodyStr := string(body)

			if detectXSSInResponse(bodyStr, payload) {
				vulns = append(vulns, Vulnerability{
					Type:        "XSS",
					URL:         target,
					Payload:     payload,
					Severity:    "中",
					Description: "检测到跨站脚本漏洞",
					Proof:       fmt.Sprintf("载荷 %s 在响应中反射", payload),
				})
				fmt.Printf("发现 XSS 漏洞: %s\n", payload)
			}
		}

		for _, inputName := range inputNames {
			testURL := target + "?" + inputName + "=" + url.QueryEscape(payload)

			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", cfg.General.UserAgent)

			resp, err := doRequestWithRetry(client, req, cfg.General.MaxRetries)
			if err != nil {
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			bodyStr := string(body)

			if detectXSSInResponse(bodyStr, payload) {
				vulns = append(vulns, Vulnerability{
					Type:        "XSS",
					URL:         testURL,
					Payload:     payload,
					Severity:    "中",
					Description: "检测到跨站脚本漏洞",
					Proof:       fmt.Sprintf("载荷 %s 在响应中反射", payload),
				})
				fmt.Printf("发现 XSS 漏洞: %s\n", payload)
			}
		}
	}

	return vulns
}

func extractInputNames(html string) []string {
	names := make([]string, 0)

	inputPattern := regexp.MustCompile(`<input[^>]*name=["']([^"']+)["'][^>]*>`)
	matches := inputPattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			names = append(names, match[1])
		}
	}

	textareaPattern := regexp.MustCompile(`<textarea[^>]*name=["']([^"']+)["'][^>]*>`)
	matches = textareaPattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			names = append(names, match[1])
		}
	}

	selectPattern := regexp.MustCompile(`<select[^>]*name=["']([^"']+)["'][^>]*>`)
	matches = selectPattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			names = append(names, match[1])
		}
	}

	return uniqueNames(names)
}

func uniqueNames(names []string) []string {
	unique := make([]string, 0)
	seen := make(map[string]bool)
	for _, name := range names {
		if !seen[name] {
			seen[name] = true
			unique = append(unique, name)
		}
	}
	return unique
}

func detectXSSInResponse(body, payload string) bool {
	if strings.Contains(body, payload) {
		return true
	}

	escapedPayload := strings.ReplaceAll(payload, "<", "&lt;")
	escapedPayload = strings.ReplaceAll(escapedPayload, ">", "&gt;")
	if strings.Contains(body, escapedPayload) {
		return true
	}

	if strings.Contains(body, "alert") && strings.Contains(body, "XSS") {
		return true
	}

	if strings.Contains(body, "onerror") && strings.Contains(body, "alert") {
		return true
	}

	return false
}

func ScanSSRF(target string, cfg *config.Config) []Vulnerability {
	vulns := make([]Vulnerability, 0)

	client := createHTTPClient(cfg)

	for _, payload := range cfg.Scanner.SSRFPayloads {
		testURL := target + "?url=" + url.QueryEscape(payload)

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", cfg.General.UserAgent)

		resp, err := doRequestWithRetry(client, req, cfg.General.MaxRetries)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		if strings.Contains(bodyStr, "127.0.0.1") || strings.Contains(bodyStr, "localhost") ||
			strings.Contains(bodyStr, "169.254.169.254") || strings.Contains(bodyStr, "meta-data") {
			vulns = append(vulns, Vulnerability{
				Type:        "SSRF",
				URL:         testURL,
				Payload:     payload,
				Severity:    "高",
				Description: "检测到服务器端请求伪造漏洞",
				Proof:       fmt.Sprintf("内部地址 %s 在响应中暴露", payload),
			})
		}
	}

	return vulns
}

func ScanCORS(target string, cfg *config.Config) []Vulnerability {
	vulns := make([]Vulnerability, 0)

	client := createHTTPClient(cfg)

	testOrigins := []string{
		"http://evil.com",
		"http://attacker.com",
		"http://localhost:3000",
		"*",
	}

	for _, origin := range testOrigins {
		req, err := http.NewRequest("OPTIONS", target, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", cfg.General.UserAgent)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "GET")

		resp, err := doRequestWithRetry(client, req, cfg.General.MaxRetries)
		if err != nil {
			continue
		}

		accessControlAllowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		accessControlAllowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
		resp.Body.Close()

		if accessControlAllowOrigin == "*" || accessControlAllowOrigin == origin {
			if accessControlAllowCredentials == "true" {
				vulns = append(vulns, Vulnerability{
					Type:        "CORS",
					URL:         target,
					Payload:     origin,
					Severity:    "高",
					Description: "检测到 CORS 配置错误：允许任意来源并携带凭据",
					Proof:       fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: true", accessControlAllowOrigin),
				})
			} else {
				vulns = append(vulns, Vulnerability{
					Type:        "CORS",
					URL:         target,
					Payload:     origin,
					Severity:    "中",
					Description: "检测到 CORS 配置错误：允许任意来源",
					Proof:       fmt.Sprintf("Access-Control-Allow-Origin: %s", accessControlAllowOrigin),
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
