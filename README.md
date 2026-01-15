# YQHunter v2.0

一个综合性 Web 安全扫描工具，使用 Go 语言编写。

## 版本更新 (v2.0)

### 新增功能
- **综合扫描 HTML 报告**：全面扫描现在生成包含所有模块结果的精美 HTML 报告
- **增强的指纹库**：包含 8654+ 条指纹识别规则
- **优化的输出格式**：自动根据文件扩展名检测输出格式
- **改进的代理支持**：支持 HTTP 和 SOCKS5 代理配置

### 重要变更
- **综合扫描输出限制**：使用 `-a` 参数进行综合扫描时，只支持 HTML 格式输出
- **其他扫描格式**：单独扫描（XSS、SSRF、CORS、目录、指纹）支持 HTML、JSON、CSV、TXT 格式
- **默认格式**：如果未指定格式或文件扩展名，默认使用 TXT 格式

## 功能特性

- **XSS 漏洞扫描**：检测跨站脚本漏洞
- **SSRF 漏洞扫描**：识别服务器端请求伪造问题
- **CORS 配置错误检测**：发现跨域资源共享问题
- **Web 爬虫**：爬取并发现所有页面和端点
- **目录扫描**：枚举隐藏目录和文件，支持自定义字典
- **指纹识别**：识别技术、框架和服务
- **API 端点发现**：查找暴露的 API 端点
- **多格式输出**：支持 HTML、JSON、CSV、TXT 格式报告

## 安装

```bash
git clone https://github.com/yourusername/yqhunter.git
cd yqhunter
go mod download
go build -o yqhunter
```

## 使用方法

### 命令行参数

```
Usage:
  yqhunter [flags]

Flags:
  -a, --all             启用所有扫描（全面扫描）
      --config string   配置文件（默认为 $HOME/.yqhunter.yaml）
  -c, --cors            启用 CORS 扫描
  -D, --depth int       爬虫最大深度 (default 3)
  -z, --dict string     字典文件路径（用于目录扫描）
  -d, --dir             启用目录扫描
  -f, --fingerprint     启用指纹识别
  -F, --format string   输出格式（html, json, csv, txt，默认根据文件扩展名自动判断）
  -h, --help            help for yqhunter
  -o, --output string   报告输出文件（支持格式：html, json, csv, txt）
      --proxy string    代理地址（例如：http://127.0.0.1:8080 或 socks5://127.0.0.1:1080）
  -p, --spider          启用爬虫
  -s, --ssrf            启用 SSRF 扫描
  -u, --url string      目标 URL（必需）
  -x, --xss             启用 XSS 扫描
```

### 基础扫描示例

```bash
# XSS 扫描
yqhunter -x -u https://example.com

# SSRF 扫描
yqhunter -s -u https://example.com

# CORS 扫描
yqhunter -c -u https://example.com

# 目录扫描
yqhunter -d -u https://example.com

# 指纹识别
yqhunter -f -u https://example.com

# 全面扫描
yqhunter -a -u https://example.com

# 爬虫
yqhunter -p -u https://example.com
```

### 使用自定义字典

```bash
# 使用自定义字典进行目录扫描（支持相对路径）
yqhunter -d -u https://example.com -z common.txt

# 使用完整路径
yqhunter -d -u https://example.com -z dictionaries/common.txt
```

### 输出结果

```bash
# 输出到 TXT 文件（默认格式）
yqhunter -x -u https://example.com -o result.txt

# 输出到 JSON 文件
yqhunter -x -u https://example.com -o result.json

# 输出到 CSV 文件
yqhunter -x -u https://example.com -o result.csv

# 输出到 HTML 报告
yqhunter -x -u https://example.com -o result.html

# 综合扫描（只支持 HTML 格式）
yqhunter -a -u https://example.com -o report.html

# 爬虫结果导出为 JSON
yqhunter -p -u https://example.com -o spider.json

# 指定输出格式
yqhunter -d -u https://example.com -o dirs.txt -F txt
```

### 使用代理

YQHunter 支持两种代理配置方式：

#### 方式 1：命令行参数（临时）

```bash
# HTTP 代理
yqhunter -a -u https://example.com --proxy http://127.0.0.1:8080

# SOCKS5 代理
yqhunter -a -u https://example.com --proxy socks5://127.0.0.1:1080
```

#### 方式 2：配置文件（推荐）

在 `config.yaml` 文件中配置代理，这样无需每次都输入代理参数：

```yaml
general:
  timeout: 30
  user_agent: "YQHunter/1.0"
  max_retries: 3
  proxy: "http://192.168.1.26:7897"  # 在这里配置代理
  concurrency: 10

scanner:
  enable_xss: true
  enable_ssrf: true
  enable_cors: true
  xss_payloads:
    - "<script>alert('XSS')</script>"
    - "<img src=x onerror=alert('XSS')>"
  dict_file: ""

spider:
  max_depth: 3
  max_pages: 100
  follow_links: true
  proxy: "http://192.168.1.26:7897"  # 爬虫代理配置
```

**代理优先级**：命令行参数 `--proxy` 会覆盖配置文件中的代理设置。

## 字典文件

YQHunter 支持自定义字典文件进行目录扫描。字典文件应包含每行一个路径：

```
admin
api
backup
config
db
debug
docs
files
images
includes
js
login
logs
media
uploads
test
tmp
vendor
web
www
.git
.env
phpmyadmin
wp-admin
```

将字典文件放在 `dictionaries` 文件夹中，或者使用 `-z` 参数指定路径。

## 输出格式

### TXT 格式

简单的文本格式，适合快速查看结果：

```
========================================
       YQHunter XSS 扫描结果
========================================

扫描类型: XSS
发现漏洞: 2

[1] URL: https://example.com/search
    Payload: <script>alert('XSS')</script>
    严重性: 高
    描述: 反射型 XSS 漏洞
    证明: 响应中包含 payload

[2] URL: https://example.com/comment
    Payload: <img src=x onerror=alert('XSS')>
    严重性: 中
    描述: 存储型 XSS 漏洞
    证明: 恶意脚本被执行
```

### JSON 格式

结构化数据格式，便于程序处理：

```json
{
  "scan_type": "XSS",
  "target": "https://example.com",
  "vulnerabilities": [
    {
      "type": "XSS",
      "url": "https://example.com/search",
      "payload": "<script>alert('XSS')</script>",
      "severity": "高",
      "description": "反射型 XSS 漏洞",
      "proof": "响应中包含 payload"
    }
  ]
}
```

### CSV 格式

表格格式，适合在 Excel 中查看：

```
类型,URL,Payload,严重性,描述,证明
XSS,https://example.com/search,<script>alert('XSS')</script>,高,反射型 XSS 漏洞,响应中包含 payload
```

### HTML 格式

#### 单独扫描 HTML 报告

详细的 HTML 报告，包含特定扫描模块的结果和可视化展示。

#### 综合扫描 HTML 报告

使用 `-a` 参数进行综合扫描时，会生成包含所有扫描模块结果的完整 HTML 报告：

- **爬虫结果**：所有发现的 URL 和页面信息
- **漏洞扫描**：XSS、SSRF、CORS 漏洞详情
- **目录扫描**：发现的目录和文件列表
- **指纹识别**：识别的技术栈和框架信息

综合扫描只支持 HTML 格式输出，会自动将其他格式转换为 HTML。

## 配置选项

### 通用设置

- `timeout`：请求超时时间（秒），默认：30
- `user_agent`：自定义 User-Agent 字符串
- `max_retries`：最大重试次数
- `proxy`：代理服务器 URL
- `concurrency`：并发请求数量

### 扫描器设置

- `enable_xss`：启用 XSS 漏洞扫描
- `enable_ssrf`：启用 SSRF 漏洞扫描
- `enable_cors`：启用 CORS 配置错误检测
- `enable_dir_scan`：启用目录扫描
- `enable_fingerprint`：启用指纹识别
- `enable_api`：启用 API 端点发现
- `dict_file`：字典文件路径

### 爬虫设置

- `max_depth`：最大爬取深度
- `max_pages`：最大爬取页面数
- `follow_links`：爬取时跟随链接
- `allow_domains`：允许的域名列表
- `exclude_paths`：排除的路径列表

## 输出

扫描器生成包含以下内容的报告：

- 漏洞详情（XSS、SSRF、CORS）
- 目录扫描结果
- 指纹识别结果
- API 端点信息
- 严重性评级
- 概念验证

## 许可证

MIT License

## 免责声明

本工具仅用于教育目的和授权的安全测试。在扫描任何目标之前，请务必获得适当的授权。
