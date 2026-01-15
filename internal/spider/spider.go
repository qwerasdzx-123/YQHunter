package spider

import (
	"yqhunter/internal/config"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

type URLInfo struct {
	URL   string
	Title string
}

type SpiderResult struct {
	URLs      []URLInfo
	Forms     []FormInfo
	Headers   map[string]string
	StartTime time.Time
	EndTime   time.Time
}

type FormInfo struct {
	Action string
	Method string
	Fields []string
}

func RunSpider(target string, cfg *config.SpiderConfig, depth int) *SpiderResult {
	result := &SpiderResult{
		URLs:      make([]URLInfo, 0),
		Forms:     make([]FormInfo, 0),
		Headers:   make(map[string]string),
		StartTime: time.Now(),
	}
	
	if depth > 0 {
		cfg.MaxDepth = depth
	}
	
	c := colly.NewCollector(
		colly.MaxDepth(cfg.MaxDepth),
		colly.Async(true),
	)
	
	if cfg.Proxy != "" {
		err := c.SetProxy(cfg.Proxy)
		if err != nil {
			fmt.Printf("设置代理失败: %v\n", err)
		} else {
			fmt.Printf("使用代理: %s\n", cfg.Proxy)
		}
	}
	
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 10,
		Delay:       1 * time.Second,
	})
	
	var mu sync.Mutex
	urlSet := make(map[string]bool)
	
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		absoluteURL := e.Request.AbsoluteURL(link)
		
		mu.Lock()
		defer mu.Unlock()
		
		if !urlSet[absoluteURL] {
			urlSet[absoluteURL] = true
			result.URLs = append(result.URLs, URLInfo{URL: absoluteURL, Title: ""})
		}
		
		if cfg.FollowLinks {
			e.Request.Visit(link)
		}
	})
	
	c.OnHTML("title", func(e *colly.HTMLElement) {
		title := e.Text
		currentURL := e.Request.URL.String()
		
		mu.Lock()
		defer mu.Unlock()
		
		for i, urlInfo := range result.URLs {
			if urlInfo.URL == currentURL || urlInfo.URL == currentURL+"/" || currentURL == urlInfo.URL+"/" {
				result.URLs[i].Title = title
				break
			}
		}
	})
	
	c.OnResponse(func(r *colly.Response) {
		mu.Lock()
		defer mu.Unlock()
		
		currentURL := r.Request.URL.String()
		
		found := false
		for _, urlInfo := range result.URLs {
			if urlInfo.URL == currentURL || urlInfo.URL == currentURL+"/" || currentURL == urlInfo.URL+"/" {
				found = true
				break
			}
		}
		
		if !found {
			result.URLs = append(result.URLs, URLInfo{URL: currentURL, Title: ""})
		}
		
		for key, values := range *r.Headers {
			if len(values) > 0 {
				result.Headers[key] = values[0]
			}
		}
	})
	
	c.OnHTML("form", func(e *colly.HTMLElement) {
		action := e.Attr("action")
		method := e.Attr("method")
		if method == "" {
			method = "GET"
		}
		
		fields := make([]string, 0)
		e.ForEach("input", func(i int, el *colly.HTMLElement) {
			name := el.Attr("name")
			if name != "" {
				fields = append(fields, name)
			}
		})
		
		mu.Lock()
		defer mu.Unlock()
		
		result.Forms = append(result.Forms, FormInfo{
			Action: action,
			Method: method,
			Fields: fields,
		})
	})
	
	for _, excludePath := range cfg.ExcludePaths {
		excludePattern := regexp.MustCompile(regexp.QuoteMeta(excludePath))
		c.DisallowedURLFilters = append(c.DisallowedURLFilters, excludePattern)
	}
	
	c.Visit(target)
	c.Wait()
	
	result.EndTime = time.Now()
	
	return result
}

func ExportResults(result *SpiderResult, format string, filename string) error {
	if filename == "" {
		filename = fmt.Sprintf("spider_results_%s.%s", time.Now().Format("20060102_150405"), format)
	}
	
	switch format {
	case "json":
		return exportJSON(result, filename)
	case "csv":
		return exportCSV(result, filename)
	case "txt":
		return exportTXT(result, filename)
	default:
		return fmt.Errorf("不支持的导出格式: %s", format)
	}
}

func exportJSON(result *SpiderResult, filename string) error {
	output := struct {
		URLs      []URLInfo         `json:"urls"`
		Forms     []FormInfo        `json:"forms"`
		Headers   map[string]string `json:"headers"`
		StartTime string            `json:"start_time"`
		EndTime   string            `json:"end_time"`
		Duration  string            `json:"duration"`
	}{
		URLs:      result.URLs,
		Forms:     result.Forms,
		Headers:   result.Headers,
		StartTime: result.StartTime.Format("2006-01-02 15:04:05"),
		EndTime:   result.EndTime.Format("2006-01-02 15:04:05"),
		Duration:  result.EndTime.Sub(result.StartTime).String(),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON 编码失败: %v", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportCSV(result *SpiderResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"类型", "URL", "标题", "详情"})

	for _, u := range result.URLs {
		writer.Write([]string{"URL", u.URL, u.Title, ""})
	}

	for _, form := range result.Forms {
		details := fmt.Sprintf("方法: %s, 字段: %v", form.Method, form.Fields)
		writer.Write([]string{"表单", form.Action, "", details})
	}

	for key, value := range result.Headers {
		writer.Write([]string{"响应头", key, "", value})
	}

	writer.Write([]string{"统计", "", "", fmt.Sprintf("总 URL 数: %d", len(result.URLs))})
	writer.Write([]string{"统计", "", "", fmt.Sprintf("总表单数: %d", len(result.Forms))})
	writer.Write([]string{"统计", "", "", fmt.Sprintf("开始时间: %s", result.StartTime.Format("2006-01-02 15:04:05"))})
	writer.Write([]string{"统计", "", "", fmt.Sprintf("结束时间: %s", result.EndTime.Format("2006-01-02 15:04:05"))})
	writer.Write([]string{"统计", "", "", fmt.Sprintf("耗时: %s", result.EndTime.Sub(result.StartTime).String())})

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportTXT(result *SpiderResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	fmt.Fprintf(file, "========================================\n")
	fmt.Fprintf(file, "       YQHunter 爬虫结果\n")
	fmt.Fprintf(file, "========================================\n\n")

	fmt.Fprintf(file, "扫描时间: %s 至 %s\n", 
		result.StartTime.Format("2006-01-02 15:04:05"), 
		result.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "总耗时: %s\n\n", result.EndTime.Sub(result.StartTime).String())

	fmt.Fprintf(file, "----------------------------------------\n")
	fmt.Fprintf(file, "发现的 URL (%d 个)\n", len(result.URLs))
	fmt.Fprintf(file, "----------------------------------------\n")
	for i, u := range result.URLs {
		if u.Title != "" {
			fmt.Fprintf(file, "%3d. %s\n", i+1, u.URL)
			fmt.Fprintf(file, "     标题: %s\n", u.Title)
		} else {
			fmt.Fprintf(file, "%3d. %s\n", i+1, u.URL)
		}
	}

	fmt.Fprintf(file, "\n----------------------------------------\n")
	fmt.Fprintf(file, "发现的表单 (%d 个)\n", len(result.Forms))
	fmt.Fprintf(file, "----------------------------------------\n")
	for i, form := range result.Forms {
		fmt.Fprintf(file, "%3d. Action: %s\n", i+1, form.Action)
		fmt.Fprintf(file, "    方法: %s\n", form.Method)
		fmt.Fprintf(file, "    字段: %v\n", form.Fields)
	}

	fmt.Fprintf(file, "\n----------------------------------------\n")
	fmt.Fprintf(file, "响应头信息\n")
	fmt.Fprintf(file, "----------------------------------------\n")
	for key, value := range result.Headers {
		fmt.Fprintf(file, "%s: %s\n", key, value)
	}

	fmt.Fprintf(file, "\n========================================\n")
	fmt.Fprintf(file, "扫描完成\n")
	fmt.Fprintf(file, "========================================\n")

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func ValidateURL(target string) bool {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return false
	}
	
	return parsedURL.Scheme == "http" || parsedURL.Scheme == "https"
}

func CheckRobotsTxt(target string) (bool, error) {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return false, err
	}
	
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", parsedURL.Scheme, parsedURL.Host)
	
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	resp, err := client.Get(robotsURL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == 200, nil
}
