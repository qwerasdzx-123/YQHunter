# SSRF 安全过滤规则

本文档定义了YQHunter项目中的SSRF（服务器端请求伪造）安全过滤规则。

## 1. 禁止的Payload类型

### 1.1 内部网络地址

```yaml
# ❌ 禁止
- "http://127.0.0.1:80"
- "http://localhost:8080"
- "http://192.168.0.1"
- "http://10.0.0.1"
```

### 1.2 云服务元数据端点

```yaml
# ❌ 禁止
- "http://169.254.169.254/latest/meta-data/"
- "http://metadata.google.internal"
```

### 1.3 文件协议

```yaml
# ❌ 禁止
- "file:///etc/passwd"
- "file:///etc/shadow"
```

### 1.4 特殊协议

```yaml
# ❌ 禁止
- "gopher://"
- "dict://"
- "ftp://"
- "ldap://"
```

## 2. 允许的测试URL

```yaml
# ✅ 允许
- "https://example.com"
- "https://httpbin.org/anything"
- "https://httpbin.org/get"
```

## 3. 安全验证函数

```go
func ValidateSSRFCandidate(url string) error {
    // 检查内部IP地址
    privateIPRanges := []string{
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.2", "172.30.", "172.31.", "192.168.", "127.",
    }
    
    for _, prefix := range privateIPRanges {
        if strings.HasPrefix(url, prefix) {
            return fmt.Errorf("URL contains private IP prefix")
        }
    }
    
    // 检查危险协议
    dangerousProtocols := []string{"file://", "gopher://", "dict://"}
    for _, proto := range dangerousProtocols {
        if strings.HasPrefix(url, proto) {
            return fmt.Errorf("URL uses dangerous protocol")
        }
    }
    
    return nil
}
```

## 4. 配置文件审查清单

- [ ] 不包含内部IP地址
- [ ] 不包含localhost引用
- [ ] 不包含特殊协议
- [ ] 不包含云服务元数据端点

## 5. 修订历史

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| 1.0 | 2026-01-20 | 初始版本 |
