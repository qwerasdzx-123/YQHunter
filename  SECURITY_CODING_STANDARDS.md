# YQHunter 安全编码规范

## 1. 概述

本文档定义了 YQHunter 项目的安全编码规范，旨在确保代码库中不包含任何可能被误用于恶意目的的安全漏洞扫描信息。所有项目贡献者必须遵守这些规范。

## 2. 核心原则

### 2.1 禁止的内容

以下内容严格禁止出现在代码库中：

- **漏洞利用代码（Exploit Code）**：任何用于利用已知漏洞的代码
- **攻击载荷（Payloads）**：专门设计用于触发安全漏洞的输入数据
- **扫描规则**：针对特定漏洞的检测逻辑和规则
- **渗透测试技术**：详细的渗透测试方法和技巧
- **敏感利用信息**：关于如何利用软件漏洞的详细说明

### 2.2 允许的内容

以下内容在符合安全最佳实践的情况下是允许的：

- **防御性安全措施**：输入验证、输出编码、安全配置
- **安全检测目的**：检测应用是否存在已知漏洞特征（用于安全评估）
- **安全最佳实践**：安全编码模式和设计模式
- **漏洞修复建议**：针对发现的问题的修复方案

## 3. 具体规范

### 3.1 SSRF (服务器端请求伪造) 规范

```go
// ❌ 错误示例 - 禁止包含
var ssrfPayloads = []string{
    "http://127.0.0.1:22",
    "http://localhost:8080",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "gopher://",
}

func testInternalNetwork(target string) {
    // 任何访问内部网络的代码
}

// ✅ 正确示例 - 允许的安全测试
var allowedTestURLs = []string{
    "https://example.com",
    "https://httpbin.org/anything",
}

func validateURL(url string) error {
    // 验证URL不包含内部地址
    if strings.HasPrefix(url, "http://127.0.0.1") {
        return errors.New("private IP address not allowed")
    }
    if strings.HasPrefix(url, "http://192.168.") {
        return errors.New("private IP address not allowed")
    }
    if strings.Contains(url, "169.254.169.254") {
        return errors.New("cloud metadata endpoint not allowed")
    }
    return nil
}
```

### 3.2 XSS (跨站脚本) 规范

```go
// ❌ 错误示例 - 禁止包含
var xssPayloads = []string{
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
}

func scanXSS(target string) []Vulnerability {
    // XSS 扫描逻辑
}

func exploitVulnerability(url string, payload string) bool {
    // 漏洞利用逻辑
}
```

### 3.3 允许的安全检测模式

```go
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

func validateInput(input string) error {
    if strings.ContainsAny(input, "<>\"'") {
        return errors.New("potentially dangerous characters detected")
    }
    return nil
}
```

### 3.3 配置文件规范

```yaml
# ❌ 错误示例 - 禁止包含
scanner:
  enable_vulnerability_scan: true
  exploit_payloads:
    - "<script>alert(1)</script>"
    - "'; DROP TABLE users;--"

# ✅ 正确示例 - 仅包含必要的配置
scanner:
  enable_security_check: true
  security_headers:
    - "X-Frame-Options"
    - "X-Content-Type-Options"
```

## 4. 代码审查清单

在进行代码审查时，需要检查以下项目：

### 4.1 必须移除的内容

- [ ] 所有漏洞利用相关的硬编码字符串
- [ ] 针对特定漏洞的检测规则
- [ ] 详细的攻击步骤说明
- [ ] 敏感的系统信息获取代码（如 `/etc/passwd`）
- [ ] 内部网络地址扫描逻辑

### 4.2 必须保留的内容

- [ ] 输入验证和清理逻辑
- [ ] 安全的错误处理
- [ ] 安全相关的配置选项
- [ ] 防御性的安全检查

## 5. 安全测试规范

### 5.1 测试数据管理

- **禁止**使用真实的敏感数据作为测试数据
- **禁止**在测试中包含可被用于恶意目的的Payload
- **使用**模拟数据和脱敏数据
- **确保**测试数据不包含个人隐私信息

### 5.2 测试环境

- 所有安全测试应在隔离的环境中进行
- 不应在生产环境中执行任何扫描或测试
- 测试数据应在测试完成后立即清理

## 6. 文档规范

### 6.1 禁止包含的内容

- 详细的漏洞利用步骤
- 具体的攻击技术说明
- 绕过安全控制的技巧
- 针对特定应用的漏洞信息

### 6.2 允许包含的内容

- 安全最佳实践建议
- 防御性安全措施说明
- 安全配置指南
- 漏洞修复建议

## 7. 依赖管理

### 7.1 依赖审查

- 所有外部依赖必须经过安全审查
- 禁止使用包含漏洞利用代码的第三方库
- 定期更新依赖以修复已知漏洞

### 7.2 依赖许可

- 确保所有依赖的许可证允许项目使用
- 避免使用许可证不明确的依赖

## 8. 事件响应

### 8.1 安全事件处理

如果发现代码库中包含不当的安全信息：

1. **立即报告**给项目维护者
2. **标记相关代码**为需要审查
3. **移除**所有不当内容
4. **更新**相关文档和测试
5. **审查**提交历史以确保完全清除

### 8.2 责任链

- **开发者**：确保不提交不当内容
- **审查者**：在代码审查中识别不当内容
- **维护者**：监督整体安全规范执行

## 9. 合规性

### 9.1 法律合规

- 确保项目不违反任何法律法规
- 遵守出口管制和制裁规定
- 尊重目标系统的使用条款

### 9.2 道德准则

- 本工具仅用于授权的安全测试
- 不支持任何形式的恶意使用
- 鼓励负责任的安全研究

## 10. 培训与意识

### 10.1 开发者培训

所有项目贡献者应了解：

- 安全编码最佳实践
- 常见的漏洞类型和防御方法
- 安全测试的道德准则
- 法律合规要求

### 10.2 持续学习

- 定期更新安全知识
- 关注安全社区的最新动态
- 参与安全相关的培训和讨论

## 11. 附录

### 11.1 术语表

- **漏洞（Vulnerability）**：软件中的安全缺陷
- **利用（Exploit）**：利用漏洞的代码或技术
- **Payload**：用于触发漏洞的输入数据
- **扫描（Scan）**：自动化检测安全问题的过程
- **防御（Defense）**：防止漏洞被利用的措施

### 11.2 参考资源

- OWASP 安全编码指南
- CWE（通用缺陷枚举）
- CVE（通用漏洞披露）
- 安全开发生命周期（SDL）

## 12. 版本控制

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| 1.0 | 2026-01-20 | 初始版本 |

## 13. 联系方式

如需报告安全问题或提出规范建议，请联系项目维护者。

---

**注意**：本文档将定期更新以反映安全领域的最新发展和最佳实践。
