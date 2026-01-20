# SSRF 安全过滤规则

本文档定义了YQHunter项目中的SSRF（服务器端请求伪造）安全过滤规则。

## 1. 概述

SSRF是一种安全漏洞，攻击者可以通过服务器端应用发送恶意请求。本文档旨在防止SSRF payload被引入代码库或配置文件中。

## 2. 禁止的Payload类型

以下类型的payload严格禁止出现在代码库和配置文件中：

### 2.1 内部网络地址

```yaml
# ❌ 禁止
- "http://127.0.0.1:80"
- "http://localhost:8080"
- "http://[::1]"
- "http://192.168.0.1"
- "http://10.0.0.1"
- "http://172.16.0.1"
```

### 2.2 云服务元数据端点

```yaml
# ❌ 禁止
- "http://169.254.169.254/latest/meta-data/"
- "http://169.254.169.254/latest/user-data/"
- "http://metadata.google.internal"
- "http://169.254.170.2/v2/credentials"
```

### 2.3 文件协议

```yaml
# ❌ 禁止
- "file:///etc/passwd"
- "file:///etc/shadow"
- "file:///proc/self/cmdline"
```

### 2.4 特殊协议

```yaml
# ❌ 禁止
- "gopher://"
- "dict://"
- "ftp://"
- "ldap://"
- "smb://"
```

### 2.5 DNS重绑定

```yaml
# ❌ 禁止
- "http://0x7f000001"  # 十六进制IP
- "http://2130706433"  # 十进制IP
- "http://[::ffff:127.0.0.1]"  # IPv4映射地址
```

## 3. 允许的测试URL

以下类型的URL可以用于安全测试：

```yaml
# ✅ 允许
- "https://example.com"
- "https://httpbin.org/anything"
- "https://httpbin.org/get"
- "https://httpbin.org/headers"
- "https://httpbin.org/status/200"
```

## 4. 安全验证规则

### 4.1 URL验证函数

```go
// ValidateSSRFCandidate 检查URL是否包含SSRF特征
func ValidateSSRFCandidate(url string) error {
    // 1. 检查内部IP地址
    privateIPRanges := []string{
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.2",
        "172.30.",
        "172.31.",
        "192.168.",
        "127.",
    }

    for _, prefix := range privateIPRanges {
        if strings.HasPrefix(url, prefix) {
            return fmt.Errorf("URL contains private IP prefix: %s", prefix)
        }
    }

    // 2. 检查localhost
    if strings.Contains(url, "localhost") || strings.Contains(url, "[::1]") {
        return errors.New("URL contains localhost reference")
    }

    // 3. 检查特殊协议
    dangerousProtocols := []string{"file://", "gopher://", "dict://", "ftp://", "ldap://"}
    for _, proto := range dangerousProtocols {
        if strings.HasPrefix(url, proto) {
            return fmt.Errorf("URL uses dangerous protocol: %s", proto)
        }
    }

    // 4. 检查云服务元数据端点
    metadataEndpoints := []string{
        "169.254.169.254",
        "metadata.google.internal",
        "169.254.170.2",
    }
    for _, endpoint := range metadataEndpoints {
        if strings.Contains(url, endpoint) {
            return fmt.Errorf("URL contains cloud metadata endpoint: %s", endpoint)
        }
    }

    return nil
}
```

### 4.2 Payload白名单

```go
// AllowedSSRFCandidates 允许的SSRF测试URL白名单
var AllowedSSRFCandidates = []string{
    "https://example.com",
    "https://httpbin.org",
    "https://httpbin.org/anything",
    "https://httpbin.org/get",
    "https://httpbin.org/headers",
    "https://httpbin.org/status/200",
    "https://ifconfig.me",
    "https://icanhazip.com",
    "https://api.ipify.org",
}

// IsAllowedSSRFCandidate 检查URL是否在白名单中
func IsAllowedSSRFCandidate(url string) bool {
    for _, allowed := range AllowedSSRFCandidates {
        if url == allowed {
            return true
        }
    }
    return false
}
```

## 5. CI/CD集成规则

### 5.1 Git Hook检查

创建一个pre-commit hook来检查配置文件中的SSRF payload：

```bash
#!/bin/bash
# pre-commit hook for SSRF payload detection

echo "Checking for SSRF payloads in config files..."

SSRF_PATTERNS=(
    "127\.0\.0\.1"
    "localhost"
    "169\.254\.169\.254"
    "file://"
    "gopher://"
    "dict://"
)

FILES=$(git diff --cached --name-only | grep -E '\.(yaml|yml|json|txt)$')

for file in $FILES; do
    for pattern in "${SSRF_PATTERNS[@]}"; do
        if grep -qE "$pattern" "$file"; then
            echo "ERROR: Potential SSRF payload pattern found in $file: $pattern"
            exit 1
        fi
    done
done

echo "SSRF payload check passed"
```

### 5.2 GitHub Actions检查

```yaml
name: Security Check

on:
  push:
    paths:
      - '**.yaml'
      - '**.yml'
      - '**.json'
      - 'config/**'

jobs:
  ssrf-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run SSRF Payload Detection
        run: |
          echo "Checking for SSRF payloads..."
          if grep -rE "127\.0\.0\.1|localhost|169\.254\.169\.254|file://|gopher://" config.yaml; then
            echo "::error::Potential SSRF payload found in config files"
            exit 1
          fi
          echo "No SSRF payloads detected"
```

## 6. 配置文件审查清单

在提交包含URL或网络配置的文件时，必须检查以下项目：

- [ ] 不包含内部IP地址（127.0.0.1, 192.168.x.x, 10.x.x.x）
- [ ] 不包含localhost引用
- [ ] 不包含特殊协议（file://, gopher://, dict://）
- [ ] 不包含云服务元数据端点
- [ ] 不包含DNS重绑定攻击模式
- [ ] 使用白名单中的测试URL或动态生成URL

## 7. 异常处理

### 7.1 允许的例外情况

以下情况可以使用内部地址：

1. **本地开发配置**（仅限开发环境）
   ```yaml
   # 仅在dev.yaml中允许
   general:
     proxy: "http://127.0.0.1:7897"  # 仅开发环境
   ```

2. **测试环境配置**
   ```yaml
   # 仅在test.yaml中允许
   scanner:
     test_server: "http://localhost:8080"  # 测试服务器
   ```

### 7.2 例外申请流程

如果确实需要使用内部地址：

1. 创建Issue说明原因
2. 获得安全团队批准
3. 在代码中添加详细注释
4. 确保只在特定环境配置中使用

## 8. 响应安全事件

如果发现SSRF payload被引入代码库：

1. **立即标记**相关代码为需要审查
2. **评估影响范围**：
   - payload是否已被使用
   - 是否可能被恶意利用
   - 影响哪些功能
3. **移除**所有不当内容
4. **更新**安全规则和检查机制
5. **通知**相关团队成员

## 9. 版本历史

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| 1.0 | 2026-01-20 | 初始版本 |

## 10. 参考资源

- [OWASP SSRF防护指南](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [PortSwigger SSRF学习资源](https://portswigger.net/web-security/ssrf)
