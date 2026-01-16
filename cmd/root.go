package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"yqhunter/internal/config"
	"yqhunter/internal/fingerprint"
	"yqhunter/internal/scanner"
	"yqhunter/internal/spider"
	"yqhunter/internal/yqfinger"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var proxyURL string

var rootCmd = &cobra.Command{
	Use:   "yqhunter",
	Short: "Web 安全扫描工具",
	Long: `YQHunter 是一个综合性的 Web 安全扫描工具，包括：
- XSS 和 SSRF 漏洞扫描
- CORS 配置错误检测
- Web 爬虫和爬取
- 目录扫描
- 指纹识别
- API 端点发现

使用示例:
  yqhunter -x https://example.com        # XSS 和 SSRF 扫描
  yqhunter -c https://example.com        # CORS 扫描
  yqhunter -d https://example.com        # 目录扫描
  yqhunter -d https://example.com -z common.txt  # 使用自定义字典进行目录扫描（自动在 dictionaries 目录查找）
  yqhunter -f https://example.com        # 指纹识别
  yqhunter -a https://example.com        # 全面扫描
  yqhunter -p https://example.com        # 爬虫

输出格式:
  yqhunter -x https://example.com -o result.txt          # 输出到 TXT 文件
  yqhunter -x https://example.com -o result.json         # 输出到 JSON 文件
  yqhunter -x https://example.com -o result.csv          # 输出到 CSV 文件
  yqhunter -x https://example.com -o result.html         # 输出到 HTML 报告
  yqhunter -a https://example.com -o report.html         # 综合扫描 HTML 报告
  yqhunter -p https://example.com -o spider.json         # 爬虫结果导出为 JSON
  yqhunter -d https://example.com -o dirs.txt          # 目录扫描输出`,
	Version: "2.1.0",
}

var targetURL string
var enableXSS bool
var enableCORS bool
var enableDir bool
var enableFingerprint bool
var enableSpider bool
var enableAll bool
var spiderDepth int
var outputReport string
var dictFile string
var useYQFinger bool

var rootRun = func(cmd *cobra.Command, args []string) {
	if targetURL == "" {
		fmt.Println("错误: 请指定目标 URL")
		fmt.Println("使用 -h 查看帮助信息")
		os.Exit(1)
	}

	cfg := config.LoadConfig(cfgFile)

	if proxyURL != "" {
		cfg.General.Proxy = proxyURL
		cfg.Spider.Proxy = proxyURL
	} else if cfg.General.Proxy != "" {
		cfg.Spider.Proxy = cfg.General.Proxy
	}

	if dictFile != "" {
		cfg.Scanner.DictFile = resolveDictPath(dictFile)
	}

	if enableAll {
		enableXSS = true
		enableCORS = true
		enableDir = true
		enableFingerprint = true
		enableSpider = true
	}

	if !enableXSS && !enableCORS && !enableDir && !enableFingerprint && !enableSpider {
		fmt.Println("错误: 请至少选择一种扫描模式")
		fmt.Println("使用 -h 查看帮助信息")
		os.Exit(1)
	}

	fmt.Printf("开始扫描目标: %s\n", targetURL)

	var spiderResults *spider.SpiderResult
	var xssVulns []scanner.Vulnerability
	var ssrfVulns []scanner.Vulnerability
	var corsVulns []scanner.Vulnerability
	var dirPaths []scanner.DirResult
	var fingerprints []fingerprint.FingerprintResult

	if enableSpider {
		fmt.Printf("开始爬取目标: %s\n", targetURL)
		spiderResults = spider.RunSpider(targetURL, &cfg.Spider, spiderDepth)
		fmt.Printf("爬取完成。发现 %d 个 URL\n", len(spiderResults.URLs))
	}

	if enableXSS {
		fmt.Printf("开始 XSS 扫描目标: %s\n", targetURL)
		xssVulns = scanner.ScanXSS(targetURL, cfg)
		fmt.Printf("XSS 扫描完成。发现 %d 个漏洞\n", len(xssVulns))

		fmt.Printf("开始 SSRF 扫描目标: %s\n", targetURL)
		ssrfVulns = scanner.ScanSSRF(targetURL, cfg)
		fmt.Printf("SSRF 扫描完成。发现 %d 个漏洞\n", len(ssrfVulns))
	}

	if enableCORS {
		fmt.Printf("开始 CORS 扫描目标: %s\n", targetURL)
		corsVulns = scanner.ScanCORS(targetURL, cfg)
		fmt.Printf("CORS 扫描完成。发现 %d 个问题\n", len(corsVulns))
	}

	if enableDir {
		fmt.Printf("开始目录扫描目标: %s\n", targetURL)
		dirPaths = scanner.ScanDirectories(targetURL, cfg)
		fmt.Printf("目录扫描完成。发现 %d 个路径\n", len(dirPaths))
	}

	if enableFingerprint {
		fmt.Printf("开始指纹识别目标: %s\n", targetURL)

		if useYQFinger {
			yqfingerPath, err := yqfinger.GetYQFingerPath()
			if err != nil {
				fmt.Printf("未找到 YQFinger 可执行文件，使用内置指纹识别: %v\n", err)
				fingerprints = getBuiltInFingerprints(targetURL, cfg)
			} else {
				client, err := yqfinger.NewYQFingerClient(yqfingerPath)
				if err != nil {
					fmt.Printf("创建 YQFinger 客户端失败: %v\n", err)
					fingerprints = getBuiltInFingerprints(targetURL, cfg)
				} else {
					results, err := client.Detect(targetURL)
					if err != nil {
						fmt.Printf("YQFinger 识别失败: %v\n", err)
						fingerprints = getBuiltInFingerprints(targetURL, cfg)
					} else {
						fmt.Printf("指纹识别完成。发现 %d 个指纹\n", len(results))
						fingerprints = convertYQFingerResults(results)
					}
				}
			}
		} else {
			fingerprints = getBuiltInFingerprints(targetURL, cfg)
		}
	}

	if outputReport == "" {
		timestamp := time.Now().Format("2006-01-02-15-04")
		outputReport = timestamp + ".txt"
		fmt.Printf("未指定输出文件，使用默认文件名: %s\n", outputReport)
	}

	if outputReport != "" {
		if enableAll {
			if !strings.HasSuffix(outputReport, ".html") {
				fmt.Printf("综合扫描只支持HTML格式输出，已自动设置为HTML格式\n")
				if !strings.HasSuffix(outputReport, ".html") {
					outputReport = outputReport + ".html"
				}
			}
			err := generateComprehensiveHTMLReport(targetURL, spiderResults, xssVulns, ssrfVulns, corsVulns, dirPaths, fingerprints, outputReport)
			if err != nil {
				fmt.Printf("生成综合报告失败: %v\n", err)
			} else {
				fmt.Printf("结果已导出到: %s\n", outputReport)
			}
		} else {
			if enableSpider && spiderResults != nil {
				spiderOutput := getModuleOutputFile(outputReport, "spider")
				err := spider.ExportResults(spiderResults, detectFormat(spiderOutput), spiderOutput)
				if err != nil {
					fmt.Printf("导出爬虫结果失败: %v\n", err)
				} else {
					fmt.Printf("爬虫结果已导出到: %s\n", spiderOutput)
				}
			}

			if enableXSS {
				allVulns := append(xssVulns, ssrfVulns...)
				xssOutput := getModuleOutputFile(outputReport, "xss")
				err := exportVulnerabilities(allVulns, "XSS+SSRF", xssOutput)
				if err != nil {
					fmt.Printf("导出 XSS+SSRF 扫描结果失败: %v\n", err)
				} else {
					fmt.Printf("XSS+SSRF 扫描结果已导出到: %s\n", xssOutput)
				}
			}

			if enableCORS {
				corsOutput := getModuleOutputFile(outputReport, "cors")
				err := exportVulnerabilities(corsVulns, "CORS", corsOutput)
				if err != nil {
					fmt.Printf("导出 CORS 扫描结果失败: %v\n", err)
				} else {
					fmt.Printf("CORS 扫描结果已导出到: %s\n", corsOutput)
				}
			}

			if enableDir {
				dirOutput := getModuleOutputFile(outputReport, "dir")
				err := exportDirResults(targetURL, dirPaths, dirOutput, detectFormat(dirOutput))
				if err != nil {
					fmt.Printf("导出目录扫描结果失败: %v\n", err)
				} else {
					fmt.Printf("目录扫描结果已导出到: %s\n", dirOutput)
				}
			}

			if enableFingerprint {
				fingerprintOutput := getModuleOutputFile(outputReport, "fingerprint")
				err := exportFingerprintResults(targetURL, fingerprints, fingerprintOutput, detectFormat(fingerprintOutput))
				if err != nil {
					fmt.Printf("导出指纹识别结果失败: %v\n", err)
				} else {
					fmt.Printf("指纹识别结果已导出到: %s\n", fingerprintOutput)
				}
			}
		}
	}
}

func useBuiltInFingerprint(targetURL string, cfg *config.Config, outputReport string) {
	fingerprintFile := cfg.Scanner.FingerprintFile
	db, err := fingerprint.LoadDatabase(fingerprintFile)
	if err != nil {
		fmt.Printf("加载指纹库失败: %v\n", err)
		fmt.Printf("使用基础指纹识别...\n")
		basicFingerprints := scanner.DetectFingerprints(targetURL, cfg)
		fmt.Printf("指纹识别完成。发现 %d 个技术\n", len(basicFingerprints))

		if outputReport != "" {
			err := exportFingerprints(targetURL, basicFingerprints, outputReport, detectFormat(outputReport))
			if err != nil {
				fmt.Printf("导出指纹识别结果失败: %v\n", err)
			}
		}
	} else {
		fingerprints := fingerprint.Detect(targetURL, db, cfg)
		fmt.Printf("指纹识别完成。发现 %d 个指纹\n", len(fingerprints))

		if outputReport != "" {
			err := exportFingerprintResults(targetURL, fingerprints, outputReport, detectFormat(outputReport))
			if err != nil {
				fmt.Printf("导出指纹识别结果失败: %v\n", err)
			}
		}
	}
}

func getBuiltInFingerprints(targetURL string, cfg *config.Config) []fingerprint.FingerprintResult {
	fingerprintFile := cfg.Scanner.FingerprintFile
	db, err := fingerprint.LoadDatabase(fingerprintFile)
	if err != nil {
		fmt.Printf("加载指纹库失败: %v\n", err)
		fmt.Printf("使用基础指纹识别...\n")
		basicFingerprints := scanner.DetectFingerprints(targetURL, cfg)
		fmt.Printf("指纹识别完成。发现 %d 个技术\n", len(basicFingerprints))
		return convertBasicFingerprints(basicFingerprints)
	} else {
		fingerprints := fingerprint.Detect(targetURL, db, cfg)
		fmt.Printf("指纹识别完成。发现 %d 个指纹\n", len(fingerprints))
		return fingerprints
	}
}

func convertBasicFingerprints(basicFingerprints []scanner.Fingerprint) []fingerprint.FingerprintResult {
	results := make([]fingerprint.FingerprintResult, 0, len(basicFingerprints))
	for _, fp := range basicFingerprints {
		results = append(results, fingerprint.FingerprintResult{
			ID:              fp.Name,
			Name:            fp.Name,
			Version:         fp.Version,
			Author:          "YQHunter",
			MatchPath:       "/",
			Status:          200,
			Method:          "GET",
			MatchType:       "header",
			MatchField:      "Server/X-Powered-By",
			Accuracy:        "",
			MatcherLocation: "header",
		})
	}
	return results
}

func convertYQFingerResults(yqResults []yqfinger.YQFingerResult) []fingerprint.FingerprintResult {
	results := make([]fingerprint.FingerprintResult, 0, len(yqResults))
	for _, result := range yqResults {
		results = append(results, fingerprint.FingerprintResult{
			ID:              result.FingerTag,
			Name:            result.FingerTag,
			Version:         "",
			Author:          "YQFinger",
			MatchPath:       result.OriginURL,
			Status:          result.OriginURLStatusCode,
			Method:          "GET",
			MatchType:       "body",
			MatchField:      "content",
			Accuracy:        "",
			MatcherLocation: "body",
		})
	}
	return results
}

func generateComprehensiveHTMLReport(targetURL string, spiderResults *spider.SpiderResult, xssVulns, ssrfVulns, corsVulns []scanner.Vulnerability, dirPaths []scanner.DirResult, fingerprints []fingerprint.FingerprintResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YQHunter - 综合安全扫描报告</title>
    <style>
        body {
            font-family: 'Microsoft YaHei', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 8px;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary-item {
            display: inline-block;
            margin: 10px 20px;
            padding: 10px 15px;
            background: white;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }
        .summary-item strong {
            display: block;
            margin-bottom: 5px;
            color: #007bff;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #007bff;
            color: white;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .vulnerability {
            margin: 10px 0;
            padding: 15px;
            border-left: 4px solid #dc3545;
            background-color: #fff3cd;
        }
        .vulnerability.high {
            border-left-color: #dc3545;
            background-color: #f8d7da;
        }
        .vulnerability.medium {
            border-left-color: #ffc107;
            background-color: #fff3cd;
        }
        .vulnerability.low {
            border-left-color: #28a745;
            background-color: #d4edda;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        .badge-high {
            background-color: #dc3545;
        }
        .badge-medium {
            background-color: #ffc107;
        }
        .badge-low {
            background-color: #28a745;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #ddd;
        }
        .url-link {
            color: #007bff;
            text-decoration: none;
            word-break: break-all;
        }
        .url-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>YQHunter - 综合安全扫描报告</h1>
        
        <div class="summary">
            <h2>扫描摘要</h2>
            <div class="summary-item">
                <strong>目标URL</strong>
                <span>` + targetURL + `</span>
            </div>
            <div class="summary-item">
                <strong>扫描时间</strong>
                <span>` + time.Now().Format("2006-01-02 15:04:05") + `</span>
            </div>
`

	if spiderResults != nil {
		html += `
            <div class="summary-item">
                <strong>爬取URL</strong>
                <span>` + fmt.Sprintf("%d", len(spiderResults.URLs)) + `</span>
            </div>
            <div class="summary-item">
                <strong>发现表单</strong>
                <span>` + fmt.Sprintf("%d", len(spiderResults.Forms)) + `</span>
            </div>
`
	}

	html += `
            <div class="summary-item">
                <strong>XSS漏洞</strong>
                <span>` + fmt.Sprintf("%d", len(xssVulns)) + `</span>
            </div>
            <div class="summary-item">
                <strong>SSRF漏洞</strong>
                <span>` + fmt.Sprintf("%d", len(ssrfVulns)) + `</span>
            </div>
            <div class="summary-item">
                <strong>CORS问题</strong>
                <span>` + fmt.Sprintf("%d", len(corsVulns)) + `</span>
            </div>
            <div class="summary-item">
                <strong>发现目录</strong>
                <span>` + fmt.Sprintf("%d", len(dirPaths)) + `</span>
            </div>
            <div class="summary-item">
                <strong>识别指纹</strong>
                <span>` + fmt.Sprintf("%d", len(fingerprints)) + `</span>
            </div>
        </div>
`

	if spiderResults != nil && len(spiderResults.URLs) > 0 {
		html += `
        <h2>爬虫结果</h2>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>标题</th>
                </tr>
            </thead>
            <tbody>
`
		for i, urlInfo := range spiderResults.URLs {
			if i < 100 {
				html += `
                <tr>
                    <td><a href="` + urlInfo.URL + `" class="url-link" target="_blank">` + urlInfo.URL + `</a></td>
                    <td>` + urlInfo.Title + `</td>
                </tr>
`
			}
		}
		if len(spiderResults.URLs) > 100 {
			html += `
                <tr>
                    <td colspan="2">... 还有 ` + fmt.Sprintf("%d", len(spiderResults.URLs)-100) + ` 个URL未显示</td>
                </tr>
`
		}
		html += `
            </tbody>
        </table>
`
	}

	if len(xssVulns) > 0 {
		html += `
        <h2>XSS 漏洞</h2>
`
		for _, vuln := range xssVulns {
			html += `
        <div class="vulnerability ` + vuln.Severity + `">
            <div><strong>类型:</strong> ` + vuln.Type + ` <span class="badge badge-` + vuln.Severity + `">` + vuln.Severity + `</span></div>
            <div><strong>URL:</strong> <a href="` + vuln.URL + `" class="url-link" target="_blank">` + vuln.URL + `</a></div>
            <div><strong>载荷:</strong> ` + vuln.Payload + `</div>
            <div><strong>证明:</strong> ` + vuln.Proof + `</div>
        </div>
`
		}
	}

	if len(ssrfVulns) > 0 {
		html += `
        <h2>SSRF 漏洞</h2>
`
		for _, vuln := range ssrfVulns {
			html += `
        <div class="vulnerability ` + vuln.Severity + `">
            <div><strong>类型:</strong> ` + vuln.Type + ` <span class="badge badge-` + vuln.Severity + `">` + vuln.Severity + `</span></div>
            <div><strong>URL:</strong> <a href="` + vuln.URL + `" class="url-link" target="_blank">` + vuln.URL + `</a></div>
            <div><strong>载荷:</strong> ` + vuln.Payload + `</div>
            <div><strong>证明:</strong> ` + vuln.Proof + `</div>
        </div>
`
		}
	}

	if len(corsVulns) > 0 {
		html += `
        <h2>CORS 配置问题</h2>
`
		for _, vuln := range corsVulns {
			html += `
        <div class="vulnerability ` + vuln.Severity + `">
            <div><strong>类型:</strong> ` + vuln.Type + ` <span class="badge badge-` + vuln.Severity + `">` + vuln.Severity + `</span></div>
            <div><strong>URL:</strong> <a href="` + vuln.URL + `" class="url-link" target="_blank">` + vuln.URL + `</a></div>
            <div><strong>来源:</strong> ` + vuln.Payload + `</div>
            <div><strong>证明:</strong> ` + vuln.Proof + `</div>
        </div>
`
		}
	}

	if len(dirPaths) > 0 {
		html += `
        <h2>目录扫描结果</h2>
        <table>
            <thead>
                <tr>
                    <th>完整URL</th>
                    <th>路径</th>
                    <th>状态码</th>
                    <th>大小</th>
                </tr>
            </thead>
            <tbody>
`
		for _, path := range dirPaths {
			html += `
                <tr>
                    <td><a href="` + path.FullURL + `" class="url-link" target="_blank">` + path.FullURL + `</a></td>
                    <td>` + path.Path + `</td>
                    <td>` + fmt.Sprintf("%d", path.StatusCode) + `</td>
                    <td>` + fmt.Sprintf("%d", path.Size) + `</td>
                </tr>
`
		}
		html += `
            </tbody>
        </table>
`
	}

	if len(fingerprints) > 0 {
		html += `
        <h2>指纹识别结果</h2>
        <table>
            <thead>
                <tr>
                    <th>名称</th>
                    <th>版本</th>
                    <th>作者</th>
                    <th>匹配路径</th>
                    <th>状态码</th>
                </tr>
            </thead>
            <tbody>
`
		for _, fp := range fingerprints {
			html += `
                <tr>
                    <td>` + fp.Name + `</td>
                    <td>` + fp.Version + `</td>
                    <td>` + fp.Author + `</td>
                    <td>` + targetURL + fp.MatchPath + `</td>
                    <td>` + fmt.Sprintf("%d", fp.Status) + `</td>
                </tr>
`
		}
		html += `
            </tbody>
        </table>
`
	}

	html += `
        <div class="footer">
            <p>由 YQHunter 生成 | 扫描时间: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
            <p>本工具仅用于教育目的和授权的安全测试</p>
        </div>
    </div>
</body>
</html>
`

	return os.WriteFile(filename, []byte(html), 0644)
}

func exportYQFingerResults(targetURL string, results []yqfinger.YQFingerResult, filename, format string) error {
	if format == "" {
		format = detectFormat(filename)
	}

	switch format {
	case "json":
		return exportYQFingerResultsJSON(targetURL, results, filename)
	case "csv":
		return exportYQFingerResultsCSV(targetURL, results, filename)
	case "txt":
		return exportYQFingerResultsTXT(targetURL, results, filename)
	default:
		return exportYQFingerResultsTXT(targetURL, results, filename)
	}
}

func exportYQFingerResultsJSON(targetURL string, results []yqfinger.YQFingerResult, filename string) error {
	data := struct {
		Target  string                    `json:"target"`
		Count   int                       `json:"count"`
		Results []yqfinger.YQFingerResult `json:"results"`
	}{
		Target:  targetURL,
		Count:   len(results),
		Results: results,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportYQFingerResultsCSV(targetURL string, results []yqfinger.YQFingerResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"目标URL", "Host", "Origin URL", "Origin Title", "Origin URL Status Code", "Site Up", "Redirect URL", "Redirect Web Title", "Redirect URL Status Code", "Finger Tag"})

	for _, result := range results {
		writer.Write([]string{
			targetURL,
			result.Host,
			result.OriginURL,
			result.OriginTitle,
			fmt.Sprintf("%d", result.OriginURLStatusCode),
			result.SiteUp,
			result.RedirectURL,
			result.RedirectWebTitle,
			fmt.Sprintf("%d", result.RedirectURLStatusCode),
			result.FingerTag,
		})
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportYQFingerResultsTXT(targetURL string, results []yqfinger.YQFingerResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "========================================\n")
	fmt.Fprintf(file, "       YQHunter 指纹识别结果 (YQFinger)\n")
	fmt.Fprintf(file, "========================================\n\n")

	fmt.Fprintf(file, "目标URL: %s\n", targetURL)
	fmt.Fprintf(file, "发现指纹: %d\n\n", len(results))

	if len(results) > 0 {
		for i, result := range results {
			fmt.Fprintf(file, "[%d] %s\n", i+1, result.OriginURL)
			fmt.Fprintf(file, "    标题: %s\n", result.OriginTitle)
			fmt.Fprintf(file, "    状态码: %d\n", result.OriginURLStatusCode)
			fmt.Fprintf(file, "    站点状态: %s\n", result.SiteUp)
			if result.RedirectURL != "" {
				fmt.Fprintf(file, "    重定向到: %s\n", result.RedirectURL)
				fmt.Fprintf(file, "    重定向标题: %s\n", result.RedirectWebTitle)
				fmt.Fprintf(file, "    重定向状态码: %d\n", result.RedirectURLStatusCode)
			}
			fmt.Fprintf(file, "    指纹: %s\n\n", result.FingerTag)
		}
	} else {
		fmt.Fprintf(file, "未发现指纹\n")
	}

	fmt.Fprintf(file, "\n========================================\n")
	fmt.Fprintf(file, "扫描完成\n")
	fmt.Fprintf(file, "========================================\n")

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportDirResultsHTML(targetURL string, paths []scanner.DirResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YQHunter 目录扫描报告</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .summary {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary h2 {
            margin-top: 0;
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .summary-item {
            display: inline-block;
            margin: 10px 20px;
            padding: 10px 15px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }
        .summary-item strong {
            display: block;
            margin-bottom: 5px;
            color: #667eea;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 30px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #667eea;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .status-200 {
            color: #28a745;
            font-weight: bold;
        }
        .status-301, .status-302, .status-303, .status-307, .status-308 {
            color: #ffc107;
            font-weight: bold;
        }
        .status-401, .status-403 {
            color: #fd7e14;
            font-weight: bold;
        }
        .status-404 {
            color: #6c757d;
        }
        .status-500 {
            color: #dc3545;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
        }
        .url-link {
            color: #667eea;
            text-decoration: none;
            word-break: break-all;
        }
        .url-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>YQHunter 目录扫描报告</h1>
        <p>目标: ` + targetURL + `</p>
    </div>

    <div class="summary">
        <h2>扫描摘要</h2>
        <div class="summary-item">
            <strong>目标URL</strong>
            <span>` + targetURL + `</span>
        </div>
        <div class="summary-item">
            <strong>发现路径</strong>
            <span>` + fmt.Sprintf("%d", len(paths)) + `</span>
        </div>
    </div>

    <h2>目录扫描结果</h2>
    <table>
        <thead>
            <tr>
                <th>完整URL</th>
                <th>路径</th>
                <th>状态码</th>
                <th>大小</th>
            </tr>
        </thead>
        <tbody>
`

	for _, path := range paths {
		statusClass := ""
		switch path.StatusCode {
		case 200:
			statusClass = "status-200"
		case 301, 302, 303, 307, 308:
			statusClass = "status-301"
		case 401, 403:
			statusClass = "status-401"
		case 404:
			statusClass = "status-404"
		case 500, 501, 502, 503, 504, 505:
			statusClass = "status-500"
		}

		html += `
            <tr>
                <td><a href="` + path.FullURL + `" class="url-link" target="_blank">` + path.FullURL + `</a></td>
                <td>` + path.Path + `</td>
                <td class="` + statusClass + `">` + fmt.Sprintf("%d", path.StatusCode) + `</td>
                <td>` + fmt.Sprintf("%d", path.Size) + `</td>
            </tr>
`
	}

	html += `
        </tbody>
    </table>

    <div class="footer">
        <p>由 YQHunter 生成 | 扫描时间: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        <p>本工具仅用于教育目的和授权的安全测试</p>
    </div>
</body>
</html>
`

	return os.WriteFile(filename, []byte(html), 0644)
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "配置文件（默认为 $HOME/.yqhunter.yaml）")
	rootCmd.PersistentFlags().StringVar(&proxyURL, "proxy", "", "代理地址（例如：http://127.0.0.1:8080 或 socks5://127.0.0.1:1080）")

	rootCmd.Flags().StringVarP(&targetURL, "url", "u", "", "目标 URL（必需）")
	rootCmd.Flags().BoolVarP(&enableXSS, "xss", "x", false, "启用 XSS 和 SSRF 扫描")
	rootCmd.Flags().BoolVarP(&enableCORS, "cors", "c", false, "启用 CORS 扫描")
	rootCmd.Flags().BoolVarP(&enableDir, "dir", "d", false, "启用目录扫描")
	rootCmd.Flags().BoolVarP(&enableFingerprint, "fingerprint", "f", false, "启用指纹识别")
	rootCmd.Flags().BoolVarP(&enableSpider, "spider", "p", false, "启用爬虫")
	rootCmd.Flags().BoolVarP(&enableAll, "all", "a", false, "启用所有扫描（全面扫描）")
	rootCmd.Flags().BoolVarP(&useYQFinger, "yqfinger", "Y", false, "使用 YQFinger 进行指纹识别")
	rootCmd.Flags().IntVarP(&spiderDepth, "depth", "D", 3, "爬虫最大深度")
	rootCmd.Flags().StringVarP(&outputReport, "output", "o", "", "报告输出文件（支持格式：html, json, csv, txt）")
	rootCmd.Flags().StringVarP(&dictFile, "dict", "z", "", "字典文件路径（用于目录扫描）")

	rootCmd.Run = rootRun
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".yqhunter")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("使用配置文件:", viper.ConfigFileUsed())
	}
}

func resolveDictPath(dictPath string) string {
	if dictPath == "" {
		return dictPath
	}

	if os.IsPathSeparator(dictPath[0]) || (len(dictPath) > 1 && dictPath[1] == ':') {
		return dictPath
	}

	if _, err := os.Stat(dictPath); err == nil {
		return dictPath
	}

	dictPathInDir := "dictionaries/" + dictPath
	if _, err := os.Stat(dictPathInDir); err == nil {
		return dictPathInDir
	}

	return dictPath
}

func createHTTPClient(timeout int) *http.Client {
	transport := &http.Transport{}

	if proxyURL != "" {
		parsedURL, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(parsedURL)
			fmt.Printf("使用代理: %s\n", proxyURL)
		} else {
			fmt.Printf("代理地址解析失败: %v\n", err)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}
}

func getModuleOutputFile(baseFile, module string) string {
	ext := ""
	if strings.Contains(baseFile, ".") {
		parts := strings.Split(baseFile, ".")
		if len(parts) > 1 {
			ext = "." + parts[len(parts)-1]
		}
	}

	baseWithoutExt := strings.TrimSuffix(baseFile, ext)
	return fmt.Sprintf("%s_%s%s", baseWithoutExt, module, ext)
}

func detectFormat(filename string) string {
	if len(filename) < 4 {
		return "txt"
	}

	ext := filename[len(filename)-4:]
	switch ext {
	case ".htm":
		return "html"
	case ".csv":
		return "csv"
	case ".txt":
		return "txt"
	}

	if len(filename) > 4 && filename[len(filename)-5:] == ".html" {
		return "html"
	}

	if len(filename) > 4 && filename[len(filename)-5:] == ".json" {
		return "json"
	}

	return "txt"
}

func exportVulnerabilities(vulns []scanner.Vulnerability, scanType, filename string) error {
	if filename == "" {
		return nil
	}

	format := detectFormat(filename)

	switch format {
	case "json":
		return exportVulnerabilitiesJSON(vulns, scanType, filename)
	case "csv":
		return exportVulnerabilitiesCSV(vulns, scanType, filename)
	case "html":
		return exportVulnerabilitiesHTML(vulns, scanType, filename)
	case "txt":
		return exportVulnerabilitiesTXT(vulns, scanType, filename)
	default:
		return exportVulnerabilitiesTXT(vulns, scanType, filename)
	}
}

func exportVulnerabilitiesJSON(vulns []scanner.Vulnerability, scanType, filename string) error {
	data := struct {
		ScanType string                  `json:"scan_type"`
		Count    int                     `json:"count"`
		Results  []scanner.Vulnerability `json:"results"`
	}{
		ScanType: scanType,
		Count:    len(vulns),
		Results:  vulns,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportVulnerabilitiesCSV(vulns []scanner.Vulnerability, scanType, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"类型", "URL", "Payload", "严重性", "描述", "证明"})

	for _, vuln := range vulns {
		writer.Write([]string{scanType, vuln.URL, vuln.Payload, vuln.Severity, vuln.Description, vuln.Proof})
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportVulnerabilitiesTXT(vulns []scanner.Vulnerability, scanType, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "========================================\n")
	fmt.Fprintf(file, "       YQHunter %s 扫描结果\n", scanType)
	fmt.Fprintf(file, "========================================\n\n")

	fmt.Fprintf(file, "扫描类型: %s\n", scanType)
	fmt.Fprintf(file, "发现漏洞: %d\n\n", len(vulns))

	if len(vulns) > 0 {
		for i, vuln := range vulns {
			fmt.Fprintf(file, "[%d] URL: %s\n", i+1, vuln.URL)
			fmt.Fprintf(file, "    Payload: %s\n", vuln.Payload)
			fmt.Fprintf(file, "    严重性: %s\n", vuln.Severity)
			fmt.Fprintf(file, "    描述: %s\n", vuln.Description)
			fmt.Fprintf(file, "    证明: %s\n\n", vuln.Proof)
		}
	} else {
		fmt.Fprintf(file, "未发现漏洞\n")
	}

	fmt.Fprintf(file, "\n========================================\n")
	fmt.Fprintf(file, "扫描完成\n")
	fmt.Fprintf(file, "========================================\n")

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportVulnerabilitiesHTML(vulns []scanner.Vulnerability, scanType, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YQHunter ` + scanType + ` 扫描报告</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .summary {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary h2 {
            margin-top: 0;
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .vulnerability-list {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .vulnerability {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            background-color: #fafafa;
        }
        .vulnerability.high {
            border-left: 4px solid #f44336;
        }
        .vulnerability.medium {
            border-left: 4px solid #ff9800;
        }
        .vulnerability.low {
            border-left: 4px solid #4caf50;
        }
        .vulnerability h3 {
            margin-top: 0;
            color: #333;
        }
        .vulnerability .url {
            color: #667eea;
            font-weight: bold;
            word-break: break-all;
        }
        .vulnerability .payload {
            background-color: #f0f0f0;
            padding: 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
            word-break: break-all;
        }
        .vulnerability .proof {
            background-color: #fff3cd;
            padding: 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
            word-break: break-all;
        }
        .no-vulnerabilities {
            text-align: center;
            padding: 40px;
            color: #666;
            font-size: 1.2em;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>YQHunter ` + scanType + ` 扫描报告</h1>
        <p>生成时间: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
    </div>

    <div class="summary">
        <h2>扫描摘要</h2>
        <p><strong>扫描类型:</strong> ` + scanType + `</p>
        <p><strong>发现漏洞:</strong> ` + fmt.Sprintf("%d", len(vulns)) + `</p>
    </div>

    <div class="vulnerability-list">
`

	if len(vulns) == 0 {
		html += `
        <div class="no-vulnerabilities">
            未发现漏洞
        </div>
`
	} else {
		for i, vuln := range vulns {
			severityClass := "low"
			if vuln.Severity == "high" {
				severityClass = "high"
			} else if vuln.Severity == "medium" {
				severityClass = "medium"
			}

			html += fmt.Sprintf(`
        <div class="vulnerability %s">
            <h3>漏洞 #%d - %s</h3>
            <p><strong>URL:</strong> <span class="url">%s</span></p>
            <p><strong>严重性:</strong> %s</p>
            <p><strong>描述:</strong> %s</p>
            <p><strong>Payload:</strong></p>
            <div class="payload">%s</div>
            <p><strong>证明:</strong></p>
            <div class="proof">%s</div>
        </div>`, severityClass, i+1, vuln.Type, vuln.URL, vuln.Severity, vuln.Description, vuln.Payload, vuln.Proof)
		}
	}

	html += `
    </div>

    <div class="footer">
        <p>本工具仅用于教育目的和授权的安全测试</p>
        <p>由 YQHunter 生成 | 扫描时间: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
    </div>
</body>
</html>`

	_, err = file.WriteString(html)
	if err != nil {
		return err
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportDirResults(targetURL string, paths []scanner.DirResult, filename, format string) error {
	if filename == "" {
		return nil
	}

	if format == "" {
		format = detectFormat(filename)
	}

	switch format {
	case "json":
		return exportDirResultsJSON(targetURL, paths, filename)
	case "csv":
		return exportDirResultsCSV(targetURL, paths, filename)
	case "html":
		return exportDirResultsHTML(targetURL, paths, filename)
	case "txt":
		return exportDirResultsTXT(targetURL, paths, filename)
	default:
		return exportDirResultsTXT(targetURL, paths, filename)
	}
}

func exportDirResultsJSON(targetURL string, paths []scanner.DirResult, filename string) error {
	data := struct {
		Target  string              `json:"target"`
		Count   int                 `json:"count"`
		Results []scanner.DirResult `json:"results"`
	}{
		Target:  targetURL,
		Count:   len(paths),
		Results: paths,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportDirResultsCSV(targetURL string, paths []scanner.DirResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"目标URL", "完整URL", "路径", "状态码", "大小"})

	for _, path := range paths {
		fullURL := targetURL
		if !strings.HasSuffix(fullURL, "/") {
			fullURL += "/"
		}
		fullURL += strings.TrimPrefix(path.Path, "/")
		writer.Write([]string{targetURL, fullURL, path.Path, fmt.Sprintf("%d", path.StatusCode), fmt.Sprintf("%d", path.Size)})
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportDirResultsTXT(targetURL string, paths []scanner.DirResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "========================================\n")
	fmt.Fprintf(file, "       YQHunter 目录扫描结果\n")
	fmt.Fprintf(file, "========================================\n\n")

	fmt.Fprintf(file, "目标URL: %s\n", targetURL)
	fmt.Fprintf(file, "发现路径: %d\n\n", len(paths))

	if len(paths) > 0 {
		for i, path := range paths {
			fullURL := targetURL
			if !strings.HasSuffix(fullURL, "/") {
				fullURL += "/"
			}
			fullURL += strings.TrimPrefix(path.Path, "/")
			fmt.Fprintf(file, "[%d] %s\n", i+1, fullURL)
			fmt.Fprintf(file, "    路径: %s\n", path.Path)
			fmt.Fprintf(file, "    状态码: %d\n", path.StatusCode)
			fmt.Fprintf(file, "    大小: %d 字节\n\n", path.Size)
		}
	} else {
		fmt.Fprintf(file, "未发现路径\n")
	}

	fmt.Fprintf(file, "\n========================================\n")
	fmt.Fprintf(file, "扫描完成\n")
	fmt.Fprintf(file, "========================================\n")

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportFingerprints(targetURL string, fingerprints []scanner.Fingerprint, filename, format string) error {
	if format == "" {
		format = detectFormat(filename)
	}

	switch format {
	case "json":
		return exportFingerprintsJSON(targetURL, fingerprints, filename)
	case "csv":
		return exportFingerprintsCSV(targetURL, fingerprints, filename)
	case "txt":
		return exportFingerprintsTXT(targetURL, fingerprints, filename)
	default:
		return exportFingerprintsTXT(targetURL, fingerprints, filename)
	}
}

func exportFingerprintsJSON(targetURL string, fingerprints []scanner.Fingerprint, filename string) error {
	data := struct {
		Target  string                `json:"target"`
		Count   int                   `json:"count"`
		Results []scanner.Fingerprint `json:"results"`
	}{
		Target:  targetURL,
		Count:   len(fingerprints),
		Results: fingerprints,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportFingerprintsCSV(targetURL string, fingerprints []scanner.Fingerprint, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"目标URL", "名称", "版本", "来源"})

	for _, fp := range fingerprints {
		writer.Write([]string{targetURL, fp.Name, fp.Version, fp.Source})
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportFingerprintsTXT(targetURL string, fingerprints []scanner.Fingerprint, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "========================================\n")
	fmt.Fprintf(file, "       YQHunter 指纹识别结果\n")
	fmt.Fprintf(file, "========================================\n\n")

	fmt.Fprintf(file, "目标URL: %s\n", targetURL)
	fmt.Fprintf(file, "发现技术: %d\n\n", len(fingerprints))

	if len(fingerprints) > 0 {
		for i, fp := range fingerprints {
			fmt.Fprintf(file, "[%d] %s\n", i+1, fp.Name)
			fmt.Fprintf(file, "    版本: %s\n", fp.Version)
			fmt.Fprintf(file, "    来源: %s\n\n", fp.Source)
		}
	} else {
		fmt.Fprintf(file, "未发现技术指纹\n")
	}

	fmt.Fprintf(file, "\n========================================\n")
	fmt.Fprintf(file, "扫描完成\n")
	fmt.Fprintf(file, "========================================\n")

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportFingerprintResults(targetURL string, fingerprints []fingerprint.FingerprintResult, filename, format string) error {
	if format == "" {
		format = detectFormat(filename)
	}

	switch format {
	case "json":
		return exportFingerprintResultsJSON(targetURL, fingerprints, filename)
	case "csv":
		return exportFingerprintResultsCSV(targetURL, fingerprints, filename)
	case "txt":
		return exportFingerprintResultsTXT(targetURL, fingerprints, filename)
	default:
		return exportFingerprintResultsTXT(targetURL, fingerprints, filename)
	}
}

func exportFingerprintResultsJSON(targetURL string, fingerprints []fingerprint.FingerprintResult, filename string) error {
	data := struct {
		Target  string                          `json:"target"`
		Count   int                             `json:"count"`
		Results []fingerprint.FingerprintResult `json:"results"`
	}{
		Target:  targetURL,
		Count:   len(fingerprints),
		Results: fingerprints,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportFingerprintResultsCSV(targetURL string, fingerprints []fingerprint.FingerprintResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"目标URL", "ID", "名称", "版本", "作者", "匹配路径", "状态码", "方法", "匹配方式", "匹配字段", "准确度", "匹配位置"})

	for _, fp := range fingerprints {
		writer.Write([]string{
			targetURL,
			fp.ID,
			fp.Name,
			fp.Version,
			fp.Author,
			fp.MatchPath,
			fmt.Sprintf("%d", fp.Status),
			fp.Method,
			fp.MatchType,
			fp.MatchField,
			fp.Accuracy,
			fp.MatcherLocation,
		})
	}

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func exportFingerprintResultsTXT(targetURL string, fingerprints []fingerprint.FingerprintResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "========================================\n")
	fmt.Fprintf(file, "       YQHunter 指纹识别结果\n")
	fmt.Fprintf(file, "========================================\n\n")

	fmt.Fprintf(file, "目标URL: %s\n", targetURL)
	fmt.Fprintf(file, "发现指纹: %d\n\n", len(fingerprints))

	if len(fingerprints) > 0 {
		for i, fp := range fingerprints {
			fmt.Fprintf(file, "[%d] %s\n", i+1, fp.Name)
			fmt.Fprintf(file, "    ID: %s\n", fp.ID)
			fmt.Fprintf(file, "    版本: %s\n", fp.Version)
			fmt.Fprintf(file, "    作者: %s\n", fp.Author)
			fmt.Fprintf(file, "    匹配路径: %s\n", fp.MatchPath)
			fmt.Fprintf(file, "    状态码: %d\n", fp.Status)
			fmt.Fprintf(file, "    方法: %s\n", fp.Method)
			fmt.Fprintf(file, "    匹配方式: %s\n", fp.MatchType)
			fmt.Fprintf(file, "    匹配字段: %s\n", fp.MatchField)
			if fp.Accuracy != "" {
				fmt.Fprintf(file, "    准确度: %s\n", fp.Accuracy)
			}
			if fp.MatcherLocation != "" {
				fmt.Fprintf(file, "    匹配位置: %s\n", fp.MatcherLocation)
			}
			fmt.Fprintf(file, "\n")
		}
	} else {
		fmt.Fprintf(file, "未发现指纹\n")
	}

	fmt.Fprintf(file, "\n========================================\n")
	fmt.Fprintf(file, "扫描完成\n")
	fmt.Fprintf(file, "========================================\n")

	fmt.Printf("结果已导出到: %s\n", filename)
	return nil
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
