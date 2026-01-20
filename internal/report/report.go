package report

import (
	"fmt"
	"os"
	"strings"
	"time"
	"yqhunter/internal/scanner"
)

func GenerateHTMLReport(result *scanner.ScanResult, outputFile string) error {
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YQHunter - 安全扫描报告</title>
    <style>
        body {
            font-family: 'Microsoft YaHei', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
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
            margin: 10px 0;
            padding: 10px;
            background-color: white;
            border-left: 4px solid #007bff;
        }
        .vulnerability {
            margin: 15px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid;
        }
        .vulnerability.high {
            background-color: #f8d7da;
            border-color: #dc3545;
        }
        .vulnerability.medium {
            background-color: #fff3cd;
            border-color: #ffc107;
        }
        .vulnerability.low {
            background-color: #d1ecf1;
            border-color: #17a2b8;
        }
        .vulnerability-type {
            font-weight: bold;
            font-size: 1.1em;
        }
        .vulnerability-url {
            color: #007bff;
            margin: 5px 0;
        }
        .vulnerability-payload {
            font-family: monospace;
            background-color: #f1f1f1;
            padding: 5px;
            border-radius: 3px;
            margin: 5px 0;
        }
        .vulnerability-proof {
            font-style: italic;
            color: #666;
            margin: 5px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #007bff;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            font-weight: bold;
        }
        .badge-high {
            background-color: #dc3545;
            color: white;
        }
        .badge-medium {
            background-color: #ffc107;
            color: #333;
        }
        .badge-low {
            background-color: #17a2b8;
            color: white;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>YQHunter - 安全扫描报告</h1>
        
        <div class="summary">
            <h2>扫描摘要</h2>
            <div class="summary-item">
                <strong>目标：</strong>` + result.Target + `
            </div>
            <div class="summary-item">
                <strong>开始时间：</strong>` + result.StartTime.Format("2006-01-02 15:04:05") + `
            </div>
            <div class="summary-item">
                <strong>结束时间：</strong>` + result.EndTime.Format("2006-01-02 15:04:05") + `
            </div>
            <div class="summary-item">
                <strong>扫描时长：</strong>` + result.EndTime.Sub(result.StartTime).String() + `
            </div>
            <div class="summary-item">
                <strong>SSRF 漏洞：</strong>` + fmt.Sprintf("%d", len(result.SSRFResults)) + `
            </div>
            <div class="summary-item">
                <strong>CORS 问题：</strong>` + fmt.Sprintf("%d", len(result.CORSResults)) + `
            </div>
            <div class="summary-item">
                <strong>发现的目录：</strong>` + fmt.Sprintf("%d", len(result.DirResults)) + `
            </div>
            <div class="summary-item">
                <strong>识别的技术：</strong>` + fmt.Sprintf("%d", len(result.Fingerprints)) + `
            </div>
            <div class="summary-item">
                <strong>发现的 API 端点：</strong>` + fmt.Sprintf("%d", len(result.APIEndpoints)) + `
            </div>
        </div>
`

	if len(result.SSRFResults) > 0 {
		html += `
        <h2>SSRF 漏洞</h2>
`
		for _, vuln := range result.SSRFResults {
			html += `
        <div class="vulnerability ` + vuln.Severity + `">
            <div class="vulnerability-type">` + vuln.Type + ` <span class="badge badge-` + vuln.Severity + `">` + vuln.Severity + `</span></div>
            <div class="vulnerability-url">URL: ` + vuln.URL + `</div>
            <div class="vulnerability-payload">载荷: ` + vuln.Payload + `</div>
            <div class="vulnerability-proof">证明: ` + vuln.Proof + `</div>
        </div>
`
		}
	}

	if len(result.CORSResults) > 0 {
		html += `
        <h2>CORS 配置问题</h2>
`
		for _, vuln := range result.CORSResults {
			html += `
        <div class="vulnerability ` + vuln.Severity + `">
            <div class="vulnerability-type">` + vuln.Type + ` <span class="badge badge-` + vuln.Severity + `">` + vuln.Severity + `</span></div>
            <div class="vulnerability-url">URL: ` + vuln.URL + `</div>
            <div class="vulnerability-payload">来源: ` + vuln.Payload + `</div>
            <div class="vulnerability-proof">证明: ` + vuln.Proof + `</div>
        </div>
`
		}
	}

	if len(result.DirResults) > 0 {
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
		for _, dir := range result.DirResults {
			fullURL := result.Target
			if !strings.HasSuffix(fullURL, "/") {
				fullURL += "/"
			}
			fullURL += strings.TrimPrefix(dir.Path, "/")
			html += `
                <tr>
                    <td>` + fullURL + `</td>
                    <td>` + dir.Path + `</td>
                    <td>` + fmt.Sprintf("%d", dir.StatusCode) + `</td>
                    <td>` + fmt.Sprintf("%d", dir.Size) + `</td>
                </tr>
`
		}
		html += `
            </tbody>
        </table>
`
	}

	if len(result.Fingerprints) > 0 {
		html += `
        <h2>指纹识别结果</h2>
        <table>
            <thead>
                <tr>
                    <th>名称</th>
                    <th>版本</th>
                    <th>来源</th>
                    <th>匹配路径</th>
                    <th>状态码</th>
                </tr>
            </thead>
            <tbody>
`
		for _, fp := range result.Fingerprints {
			html += `
                <tr>
                    <td>` + fp.Name + `</td>
                    <td>` + fp.Version + `</td>
                    <td>` + fp.Source + `</td>
                    <td>` + result.Target + `</td>
                    <td>-</td>
                </tr>
`
		}
		html += `
            </tbody>
        </table>
`
	}

	if len(result.APIEndpoints) > 0 {
		html += `
        <h2>API 端点</h2>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>方法</th>
                </tr>
            </thead>
            <tbody>
`
		for _, api := range result.APIEndpoints {
			html += `
                <tr>
                    <td>` + api.URL + `</td>
                    <td>` + api.Method + `</td>
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

	return os.WriteFile(outputFile, []byte(html), 0644)
}

func PrintSummary(result *scanner.ScanResult) {
	fmt.Println("\n=== 扫描摘要 ===")
	fmt.Printf("目标: %s\n", result.Target)
	fmt.Printf("开始时间: %s\n", result.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("结束时间: %s\n", result.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("扫描时长: %s\n", result.EndTime.Sub(result.StartTime))

	fmt.Println("\n=== 漏洞统计 ===")
	fmt.Printf("SSRF 漏洞: %d\n", len(result.SSRFResults))
	fmt.Printf("CORS 问题: %d\n", len(result.CORSResults))

	fmt.Println("\n=== 其他发现 ===")
	fmt.Printf("发现的目录: %d\n", len(result.DirResults))
	fmt.Printf("识别的技术: %d\n", len(result.Fingerprints))
	fmt.Printf("发现的 API 端点: %d\n", len(result.APIEndpoints))

	if len(result.SSRFResults) > 0 {
		fmt.Println("\n=== SSRF 漏洞详情 ===")
		for i, vuln := range result.SSRFResults {
			fmt.Printf("%d. [%s] %s\n", i+1, vuln.Severity, vuln.URL)
			fmt.Printf("   载荷: %s\n", vuln.Payload)
			fmt.Printf("   证明: %s\n", vuln.Proof)
		}
	}

	if len(result.CORSResults) > 0 {
		fmt.Println("\n=== CORS 问题详情 ===")
		for i, vuln := range result.CORSResults {
			fmt.Printf("%d. [%s] %s\n", i+1, vuln.Severity, vuln.URL)
			fmt.Printf("   来源: %s\n", vuln.Payload)
			fmt.Printf("   证明: %s\n", vuln.Proof)
		}
	}

	if len(result.DirResults) > 0 {
		fmt.Println("\n=== 目录扫描结果 ===")
		for _, dir := range result.DirResults {
			fmt.Printf("  %s [%d] (%d 字节)\n", dir.Path, dir.StatusCode, dir.Size)
		}
	}

	if len(result.Fingerprints) > 0 {
		fmt.Println("\n=== 指纹识别结果 ===")
		for _, fp := range result.Fingerprints {
			fmt.Printf("  %s: %s (来源: %s)\n", fp.Name, fp.Version, fp.Source)
		}
	}

	if len(result.APIEndpoints) > 0 {
		fmt.Println("\n=== API 端点 ===")
		for _, api := range result.APIEndpoints {
			fmt.Printf("  %s [%s]\n", api.URL, api.Method)
		}
	}
}
