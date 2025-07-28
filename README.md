### JSAuditX -- JavaScript安全审计工具分析

#### 一、代码功能概述

### **JSAuditX**，主要功能包括：

1. **漏洞扫描**：检测XSS、URL重定向、SQL注入、CSRF、SSRF安全漏洞
2. **敏感信息提取**：识别API密钥、JWT令牌、硬编码凭证、敏感注释
3. **端点分析**：提取API端点和URL字符串
4. **多源支持**：支持URL、本地文件、目录的批量扫描
5. **性能优化**：多线程处理、内存控制、进度显示

使用方法：

```
python JSAuditX.py -t "url" -o export.json
```



```py
usage: JSAuditX.py [-h] -t TARGET -o OUTPUT [-w WORDLIST] [--threads THREADS]
                   [--passive] [--max-memory MAX_MEMORY] [--quiet]

JSAuditX - 高级JavaScript安全审计工具

options:
  -h, --help            显示帮助信息并退出
  -t, --target TARGET   目标URL/文件/目录路径或包含目标的文本文件
  -o, --output OUTPUT   输出JSON文件路径
  -w, --wordlist WORDLIST
                        自定义敏感关键词文件路径
  --threads THREADS     线程数 (默认: 5)
  --passive             被动模式(仅分析不发送请求)
  --max-memory MAX_MEMORY
                        最大内存使用(MB) (默认: 512)
  --quiet               静默模式(不显示输出)
```

该工具适合用于：

- Web应用安全审计
- 甲方安全团队日常巡检
- 渗透测试中的JS静态分析
- 开发阶段的代码安全审查
