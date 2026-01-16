package fingerprint

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"yqhunter/internal/config"

	"golang.org/x/text/encoding/simplifiedchinese"
	"gopkg.in/yaml.v2"
)

var (
	reTitle = regexp.MustCompile(`(?im)<\s*title.*>(.*?)<\s*/\s*title>`)
)

type Matcher struct {
	Location         string   `yaml:"location"`         // body, header, favicon, webPath, bodyHash
	Words            []string `yaml:"words"`            // 关键字列表
	Hash             []string `yaml:"hash"`             // favicon hash 列表
	Path             string   `yaml:"path"`             // webPath 的路径
	Condition        string   `yaml:"condition"`        // and, or
	Accuracy         string   `yaml:"accuracy"`         // 准确度
	AllowErrorStatus bool     `yaml:"allowErrorStatus"` // 是否允许在错误状态码下匹配
	Type             string   `yaml:"type"`             // regex, word
}

func extractTitle(bodyStr string) string {
	for _, match := range reTitle.FindAllString(bodyStr, -1) {
		title := match
		title = strings.TrimSpace(title)
		if title != "" {
			return title
		}
	}
	return ""
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
		}
	}

	return nil, lastErr
}

type FingerprintRule struct {
	ID          string    `yaml:"id"`
	Name        string    `yaml:"name"`
	Author      string    `yaml:"author"`
	Description string    `yaml:"description"`
	Tags        []string  `yaml:"tags"`
	Paths       []string  `yaml:"paths"`
	Method      string    `yaml:"method"`
	Matchers    []Matcher `yaml:"matchers"`
	Keywords    []string  `yaml:"keywords"`
	Headers     []string  `yaml:"headers"`
	BodyRegex   string    `yaml:"body_regex"`
}

type FingerprintResult struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Author          string `json:"author"`
	MatchPath       string `json:"match_path"`
	Status          int    `json:"status"`
	Method          string `json:"method"`
	MatchType       string `json:"match_type"`
	MatchField      string `json:"match_field"`
	Accuracy        string `json:"accuracy"`
	MatcherLocation string `json:"matcher_location"`
}

type FingerprintDatabase struct {
	Rules []FingerprintRule `yaml:"rules"`
}

func LoadDatabase(configPath string) (*FingerprintDatabase, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取指纹库文件失败: %v", err)
	}

	var db FingerprintDatabase
	err = yaml.Unmarshal(data, &db)
	if err != nil {
		return nil, fmt.Errorf("解析指纹库文件失败: %v", err)
	}

	return &db, nil
}

func Detect(target string, db *FingerprintDatabase, cfg *config.Config) []FingerprintResult {
	results := make([]FingerprintResult, 0)
	var mu sync.Mutex

	fmt.Printf("加载指纹库，共 %d 条规则\n", len(db.Rules))

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     30 * time.Second,
	}

	if cfg.General.SkipSSLVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	if cfg.General.Proxy != "" {
		proxyURL, err := url.Parse(cfg.General.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Timeout:   time.Duration(cfg.General.Timeout) * time.Second,
		Transport: transport,
	}

	type ResponseCache struct {
		StatusCode int
		Header     http.Header
		BodyStr    string
		WebTitle   string
		HeaderStr  string
	}

	responseCache := make(map[string]*ResponseCache)
	var cacheMu sync.Mutex

	getResponse := func(path string) (*ResponseCache, error) {
		cacheMu.Lock()
		if cached, exists := responseCache[path]; exists {
			cacheMu.Unlock()
			return cached, nil
		}
		cacheMu.Unlock()

		method := "GET"
		fullURL := strings.TrimSuffix(target, "/") + path

		req, err := http.NewRequest(method, fullURL, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

		resp, err := doRequestWithRetry(client, req, cfg.General.MaxRetries)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		bodyStr := string(body)

		if !utf8.Valid(body) {
			body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
			bodyStr = string(body)
		}

		webTitle := extractTitle(bodyStr)

		headerStr := ""
		for key, values := range resp.Header {
			for _, value := range values {
				headerStr += key + ": " + value + "\n"
			}
		}

		cache := &ResponseCache{
			StatusCode: resp.StatusCode,
			Header:     resp.Header,
			BodyStr:    bodyStr,
			WebTitle:   webTitle,
			HeaderStr:  headerStr,
		}

		cacheMu.Lock()
		responseCache[path] = cache
		cacheMu.Unlock()

		return cache, nil
	}

	homeResp, err := getResponse("/")
	if err != nil {
		fmt.Printf("获取主页失败: %v\n", err)
		return results
	}

	matchedFingerprints := make(map[string]bool)

	for _, rule := range db.Rules {
		hasValidMatcher := false
		for _, matcher := range rule.Matchers {
			if len(matcher.Words) > 0 || len(matcher.Hash) > 0 {
				hasValidMatcher = true
			}
		}
		if !hasValidMatcher {
			continue
		}

		matchedLocal := false
		matchType := "path"
		matchField := "status"
		matcherLocation := ""
		accuracy := ""

		if len(rule.Matchers) > 0 {
			for _, matcher := range rule.Matchers {
				if checkMatcher(matcher, homeResp.StatusCode, homeResp.Header, homeResp.BodyStr, target, homeResp.WebTitle) {
					matchedLocal = true
					matchType = matcher.Location
					matcherLocation = matcher.Location
					if matcher.Accuracy != "" {
						accuracy = matcher.Accuracy
					}
					if len(matcher.Words) > 0 {
						matchField = strings.Join(matcher.Words, ", ")
					}
					break
				}
			}
		} else {
			if homeResp.StatusCode >= 200 && homeResp.StatusCode < 400 {
				matchedLocal = true
			} else if homeResp.StatusCode == 403 {
				matchedLocal = true
			}

			if matchedLocal {
				if len(rule.Headers) > 0 {
					for _, header := range rule.Headers {
						for _, values := range homeResp.Header {
							for _, value := range values {
								if strings.Contains(strings.ToLower(value), strings.ToLower(header)) {
									matchedLocal = true
									matchType = "header"
									matchField = header
									break
								}
							}
							if matchType == "header" {
								break
							}
						}
					}
				}

				if matchedLocal && len(rule.Keywords) > 0 {
					for _, keyword := range rule.Keywords {
						if strings.Contains(strings.ToLower(homeResp.BodyStr), strings.ToLower(keyword)) {
							matchType = "keyword"
							matchField = keyword
							break
						}
					}
				}

				if matchedLocal && rule.BodyRegex != "" {
					if strings.Contains(strings.ToLower(homeResp.BodyStr), strings.ToLower(rule.BodyRegex)) {
						matchType = "body_regex"
						matchField = rule.BodyRegex
					}
				}
			}
		}

		if matchedLocal {
			mu.Lock()
			results = append(results, FingerprintResult{
				ID:              rule.ID,
				Name:            rule.Name,
				Version:         rule.Description,
				Author:          rule.Author,
				MatchPath:       "/",
				Status:          homeResp.StatusCode,
				Method:          "GET",
				MatchType:       matchType,
				MatchField:      matchField,
				Accuracy:        accuracy,
				MatcherLocation: matcherLocation,
			})
			matchedFingerprints[rule.ID] = true
			if homeResp.StatusCode == 403 {
				fmt.Printf("发现指纹: %s (路径: /, 状态码: %d - 需要认证, 匹配方式: %s, 匹配字段: %s)\n", rule.Name, homeResp.StatusCode, matchType, matchField)
			} else {
				fmt.Printf("发现指纹: %s (路径: /, 状态码: %d, 匹配方式: %s, 匹配字段: %s)\n", rule.Name, homeResp.StatusCode, matchType, matchField)
			}
			mu.Unlock()
		}
	}

	for _, rule := range db.Rules {
		if matchedFingerprints[rule.ID] {
			continue
		}

		hasValidMatcher := false
		for _, matcher := range rule.Matchers {
			if len(matcher.Words) > 0 || len(matcher.Hash) > 0 {
				hasValidMatcher = true
			}
		}
		if !hasValidMatcher {
			continue
		}

		paths := rule.Paths
		if len(paths) == 0 && len(rule.Matchers) > 0 {
			for _, matcher := range rule.Matchers {
				if matcher.Location == "webPath" && matcher.Path != "" {
					paths = append(paths, matcher.Path)
				}
			}
		}
		if len(paths) == 0 {
			continue
		}

		for _, path := range paths {
			if path == "/" {
				continue
			}

			respCache, err := getResponse(path)
			if err != nil {
				continue
			}

			matchedLocal := false
			matchType := "path"
			matchField := "status"
			matcherLocation := ""
			accuracy := ""

			if len(rule.Matchers) > 0 {
				for _, matcher := range rule.Matchers {
					if checkMatcher(matcher, respCache.StatusCode, respCache.Header, respCache.BodyStr, target, respCache.WebTitle) {
						matchedLocal = true
						matchType = matcher.Location
						matcherLocation = matcher.Location
						if matcher.Accuracy != "" {
							accuracy = matcher.Accuracy
						}
						if len(matcher.Words) > 0 {
							matchField = strings.Join(matcher.Words, ", ")
						}
						break
					}
				}
			} else {
				if respCache.StatusCode >= 200 && respCache.StatusCode < 400 {
					matchedLocal = true
				} else if respCache.StatusCode == 403 {
					matchedLocal = true
				}

				if matchedLocal {
					if len(rule.Headers) > 0 {
						for _, header := range rule.Headers {
							for _, values := range respCache.Header {
								for _, value := range values {
									if strings.Contains(strings.ToLower(value), strings.ToLower(header)) {
										matchedLocal = true
										matchType = "header"
										matchField = header
										break
									}
								}
								if matchType == "header" {
									break
								}
							}
						}
					}

					if matchedLocal && len(rule.Keywords) > 0 {
						for _, keyword := range rule.Keywords {
							if strings.Contains(strings.ToLower(respCache.BodyStr), strings.ToLower(keyword)) {
								matchType = "keyword"
								matchField = keyword
								break
							}
						}
					}

					if matchedLocal && rule.BodyRegex != "" {
						if strings.Contains(strings.ToLower(respCache.BodyStr), strings.ToLower(rule.BodyRegex)) {
							matchType = "body_regex"
							matchField = rule.BodyRegex
						}
					}
				}
			}

			if matchedLocal {
				mu.Lock()
				results = append(results, FingerprintResult{
					ID:              rule.ID,
					Name:            rule.Name,
					Version:         rule.Description,
					Author:          rule.Author,
					MatchPath:       path,
					Status:          respCache.StatusCode,
					Method:          "GET",
					MatchType:       matchType,
					MatchField:      matchField,
					Accuracy:        accuracy,
					MatcherLocation: matcherLocation,
				})
				matchedFingerprints[rule.ID] = true
				if respCache.StatusCode == 403 {
					fmt.Printf("发现指纹: %s (路径: %s, 状态码: %d - 需要认证, 匹配方式: %s, 匹配字段: %s)\n", rule.Name, path, respCache.StatusCode, matchType, matchField)
				} else {
					fmt.Printf("发现指纹: %s (路径: %s, 状态码: %d, 匹配方式: %s, 匹配字段: %s)\n", rule.Name, path, respCache.StatusCode, matchType, matchField)
				}
				mu.Unlock()
				break
			}
		}
	}

	return results
}

func checkMatcher(matcher Matcher, statusCode int, header http.Header, bodyStr string, target string, webTitle string) bool {
	bodyLower := strings.ToLower(bodyStr)
	titleLower := strings.ToLower(webTitle)
	statusOK := statusCode >= 200 && statusCode < 400
	statusAuth := statusCode == 401 || statusCode == 403

	if !statusOK && !statusAuth && !matcher.AllowErrorStatus {
		return false
	}

	switch matcher.Location {
	case "title":
		if len(matcher.Words) == 0 {
			return false
		}
		if matcher.Type == "regex" {
			re := regexp.MustCompile(strings.Join(matcher.Words, "|"))
			return re.MatchString(titleLower)
		}
		if matcher.Condition == "and" {
			for _, word := range matcher.Words {
				if !strings.Contains(titleLower, strings.ToLower(word)) {
					return false
				}
			}
			return true
		} else {
			for _, word := range matcher.Words {
				if strings.Contains(titleLower, strings.ToLower(word)) {
					return true
				}
			}
		}

	case "body":
		if len(matcher.Words) == 0 {
			return false
		}
		if matcher.Type == "regex" {
			re := regexp.MustCompile(strings.Join(matcher.Words, "|"))
			return re.MatchString(bodyLower)
		}
		if matcher.Condition == "and" {
			for _, word := range matcher.Words {
				if !strings.Contains(bodyLower, strings.ToLower(word)) {
					return false
				}
			}
			return true
		} else {
			for _, word := range matcher.Words {
				if strings.Contains(bodyLower, strings.ToLower(word)) {
					return true
				}
			}
		}

	case "header":
		if len(matcher.Words) == 0 {
			return false
		}
		if matcher.Type == "regex" {
			headerStr := ""
			for key, values := range header {
				for _, value := range values {
					headerStr += key + ": " + value + "\n"
				}
			}
			re := regexp.MustCompile(strings.Join(matcher.Words, "|"))
			return re.MatchString(headerStr)
		}
		for _, word := range matcher.Words {
			for _, values := range header {
				for _, value := range values {
					if strings.Contains(strings.ToLower(value), strings.ToLower(word)) {
						return true
					}
				}
			}
		}

	case "webPath":
		if matcher.Path == "" {
			return false
		}
		if len(matcher.Words) == 0 {
			return statusOK
		}
		if matcher.Type == "regex" {
			re := regexp.MustCompile(strings.Join(matcher.Words, "|"))
			return re.MatchString(bodyLower)
		}
		for _, word := range matcher.Words {
			if strings.Contains(bodyLower, strings.ToLower(word)) {
				return true
			}
		}

	case "favicon":
		return false

	case "bodyHash":
		return false
	}

	return false
}

func ConvertLegacyFormat(legacyPath string, outputPath string) error {
	data, err := ioutil.ReadFile(legacyPath)
	if err != nil {
		return fmt.Errorf("读取旧格式文件失败: %v", err)
	}

	var legacyData map[string][]string
	err = yaml.Unmarshal(data, &legacyData)
	if err != nil {
		return fmt.Errorf("解析旧格式文件失败: %v", err)
	}

	db := &FingerprintDatabase{
		Rules: make([]FingerprintRule, 0),
	}

	for name, paths := range legacyData {
		db.Rules = append(db.Rules, FingerprintRule{
			Name:   name,
			Paths:  paths,
			Method: "GET",
		})
	}

	outputData, err := yaml.Marshal(db)
	if err != nil {
		return fmt.Errorf("生成新格式文件失败: %v", err)
	}

	err = ioutil.WriteFile(outputPath, outputData, 0644)
	if err != nil {
		return fmt.Errorf("写入新格式文件失败: %v", err)
	}

	return nil
}
