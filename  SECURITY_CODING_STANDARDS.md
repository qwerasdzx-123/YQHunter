# YQHunter 安全编码规范

## 1. 概述

本文档定义了YQHunter项目的安全编码规范，确保代码库中不包含任何可能被误用于恶意目的的安全漏洞扫描信息。

## 2. 核心原则

### 2.1 禁止的内容

以下内容严格禁止出现在代码库中：

- **漏洞利用代码（Exploit Code）**：任何用于利用已知漏洞的代码
- **攻击载荷（Payloads）**：专门设计用于触发安全漏洞的输入数据
- **扫描规则**：针对特定漏洞的检测逻辑和规则

### 2.2 允许的内容

以下内容在符合安全最佳实践的情况下是允许的：

- **防御性安全措施**：输入验证、输出编码、安全配置
- **安全检测目的**：检测应用是否存在已知漏洞特征
- **安全最佳实践**：安全编码模式和设计模式

## 3. SSRF 规范

```go
// ❌ 错误示例 - 禁止包含
var ssrfPayloads = []string{
    "http://127.0.0.1:22",
    "http://localhost:8080",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
}

// ✅ 正确示例 - 允许的安全测试
var allowedTestURLs = []string{
    "https://example.com",
    "https://httpbin.org/anything",
}

func validateURL(url string) error {
    if strings.HasPrefix(url, "http://127.0.0.1") {
        return errors.New("private IP address not allowed")
    }
    if strings.Contains(url, "169.254.169.254") {
        return errors.New("cloud metadata endpoint not allowed")
    }
    return nil
}
```

## 4. XSS 规范

```go
// ❌ 错误示例 - 禁止包含
var xssPayloads = []string{
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
}

// ✅ 正确示例 - 允许的安全检测
func checkSecurityHeaders(resp *http.Response) []SecurityIssue {
    issues := []SecurityIssue{}
    if resp.Header.Get("X-Frame-Options") == "" {
        issues = append(issues, SecurityIssue{
            Type:        "Missing Security Header",
            Severity:    "medium",
            Description: "X-Frame-Options header is missing",
        })
    }
    return issues
}
```

## 5. 代码审查清单

- [ ] 所有用户输入都经过验证
- [ ] 没有使用硬编码的敏感信息
- [ ] 文件操作使用最小必要权限
- [ ] HTTP客户端配置安全
- [ ] 错误信息不泄露敏感数据

## 6. 修订历史

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| 1.0 | 2026-01-20 | 初始版本 |
