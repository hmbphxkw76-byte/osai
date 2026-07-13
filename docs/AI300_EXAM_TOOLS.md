# OffSec AI-300 考试工具参考指南

> **符合最佳实践原则优先**

> **声明**：本文档所列第三方 AI 安全工具仅供学习参考和备考使用，**非 RedTeam-AI 项目的代码依赖**，与项目的 Library-First 原则和工具依赖最小化规则不冲突。

> **更新时间**：2026-07-12

---

## 一、官方 Kali Linux 工具（预装，考试可用）

### 1.1 侦察阶段（AI-300 Ch2）

| 工具 | 用途 | AI 安全场景 | 使用示例 |
|------|------|------------|---------|
| **nmap** | 网络扫描 | 发现 AI 基础设施、模型 API 端口、向量数据库 | `nmap -sV -A target_ip` |
| **gobuster** | 目录枚举 | 发现隐藏的 AI API 端点、管理后台 | `gobuster dir -u http://target -w wordlist.txt` |
| **feroxbuster** | 快速目录扫描 | 枚举 LLM API 路径、RAG 知识库端点 | `feroxbuster -u http://target -w wordlist.txt` |
| **ffuf** | fuzz 测试 | 参数 fuzz、API 端点发现、提示注入测试 | `ffuf -w payloads.txt -X POST -d '{"prompt":"FUZZ"}' http://target/v1/chat` |
| **theHarvester** | OSINT | 收集 AI 系统相关的公开信息、API 密钥泄露 | `theHarvester -d target.com -b all` |
| **amass** | 子域名枚举 | 发现子域名上的 AI 服务、shadow AI | `amass enum -d target.com` |
| **dnsrecon** | DNS 侦察 | 发现 AI 服务的 DNS 配置、API 网关 | `dnsrecon -d target.com` |

### 1.2 API 测试阶段（AI-300 Ch3/Ch5/Ch7）

| 工具 | 用途 | AI 安全场景 | 使用示例 |
|------|------|------------|---------|
| **Burp Suite** | Web 应用测试 | 拦截 AI API 请求、测试提示注入、MCP 工具劫持 | 拦截 `/v1/chat/completions` 请求，修改 prompt 参数 |
| **OWASP ZAP** | 自动化扫描 | 扫描 AI 接口的 XSS、注入、认证缺陷 | `zap-cli -t http://target quick-scan` |
| **caido** | 现代 Web 安全工具 | AI API 流量分析、请求篡改 | 分析 LLM API 请求响应模式 |
| **wireshark** | 网络流量分析 | 监控 AI 模型与外部 API 的通信、数据泄露检测 | 过滤 HTTP/HTTPS 流量，分析 API 密钥传输 |

### 1.3 漏洞利用阶段（AI-300 Ch8/Ch9）

| 工具 | 用途 | AI 安全场景 | 使用示例 |
|------|------|------------|---------|
| **metasploit-framework** | 漏洞利用 | 利用 AI 基础设施漏洞、容器逃逸、供应链攻击 | `msfconsole` → `search ai` |
| **sqlmap** | SQL 注入 | 测试后端数据库（训练数据、模型输出存储） | `sqlmap -u http://target/api/data?id=1` |
| **hydra** | 暴力破解 | 测试 AI 系统认证机制、API 密钥破解 | `hydra -L users.txt -P pass.txt target http-post-form "/login:user=^USER^&pass=^PASS^"` |
| **hashcat** | 密码破解 | 破解保护 AI 训练管道的凭据 | `hashcat -m 0 hashes.txt wordlist.txt` |

### 1.4 数据分析阶段（AI-300 Ch6/Ch10）

| 工具 | 用途 | AI 安全场景 | 使用示例 |
|------|------|------------|---------|
| **maltego** | 数据关系映射 | AI 供应链风险分析、数据来源追踪 | 构建 AI 服务依赖关系图 |
| **whatweb** | 技术识别 | 识别 AI 协议（MCP、Ollama、vLLM）、护栏类型 | `whatweb http://target` |

---

## 二、AI 专用安全工具（需手动安装，学习参考）

### 2.1 核心 AI 安全测试工具

| 工具 | 项目地址 | 功能 | AI-300 覆盖章节 | 安装方式 |
|------|---------|------|---------------|---------|
| **Promptix** | [GitHub](https://github.com/xm4skbyt3z/promptix) | LLM 安全扫描器：提示注入、越狱、系统提示泄露、Unicode 绕过 | Ch3 | `git clone https://github.com/xm4skbyt3z/promptix && cd promptix && pip install .` |
| **PyRIT** | [Microsoft](https://github.com/microsoft/PyRIT) | AI 红队工具：多模态攻击、护栏绕过、RAG 投毒 | Ch3/Ch5 | `pip install pyrit`（项目 optional 依赖） |
| **Garak** | [GitHub](https://github.com/leondz/garak) | LLM 安全测试框架：越狱、泄露、对抗性攻击 | Ch3 | `pip install garak` |
| **llm-attacks** | [GitHub](https://github.com/llm-attacks/llm-attacks) | 自动生成对抗性提示词、护栏绕过 | Ch3 | `git clone https://github.com/llm-attacks/llm-attacks && cd llm-attacks && pip install .` |
| **PentestGPT** | [GitHub](https://github.com/CyberPunkMetalHead/PentestGPT) | AI 驱动的渗透测试辅助工具 | Ch11 | 参考官方文档 |

### 2.2 MCP 相关工具

| 工具 | 用途 | AI-300 覆盖章节 | 安装方式 |
|------|------|---------------|---------|
| **mcp-kali-server** | 通过 MCP 协议让 AI 调用 Kali 工具 | Ch7 | `pip install mcp-kali-server` |
| **llama.cpp** | 本地 LLM 推理 | Ch2/Ch3 | 源码编译安装 |
| **Ollama** | 本地模型管理 | Ch2/Ch3 | 官网下载安装 |

---

## 三、工具使用优先级建议

### P0 - 必须掌握（考试高频）

| 工具 | 掌握要点 | AI-300 考点 |
|------|---------|-------------|
| **Burp Suite** | 拦截、修改 AI API 请求，测试提示注入 | Ch3: 提示注入 |
| **ffuf** | 参数 fuzz、API 端点发现 | Ch2: 攻击面侦察 |
| **nmap** | 端口扫描、服务识别 | Ch2: AI 基础设施发现 |
| **gobuster** | 目录枚举、隐藏端点发现 | Ch2: 攻击面侦察 |
| **metasploit** | 漏洞利用、后渗透 | Ch9: 基础设施攻击 |
| **sqlmap** | 数据库攻击 | Ch8: 供应链攻击 |

### P1 - 建议掌握

| 工具 | 掌握要点 | AI-300 考点 |
|------|---------|-------------|
| **Promptix** | 自动化 LLM 安全扫描 | Ch3: 提示注入、护栏绕过 |
| **PyRIT** | 高级 AI 红队技术 | Ch3/Ch5: RAG 投毒 |
| **wireshark** | 流量分析、数据泄露检测 | Ch2/Ch8 |
| **maltego** | 威胁建模、供应链分析 | Ch10: 威胁建模 |

### P2 - 了解即可

| 工具 | 用途 | AI-300 考点 |
|------|------|-------------|
| **Garak** | LLM 安全研究框架 | Ch3: 对抗性攻击 |
| **llm-attacks** | 对抗性提示词生成 | Ch3: 护栏绕过 |
| **PentestGPT** | AI 辅助渗透测试 | Ch11: 综合演练 |

---

## 四、考试环境注意事项

### 4.1 工具可用性

| 工具类型 | 可用性 | 备注 |
|----------|--------|------|
| Kali 预装工具 | ✅ 可用 | nmap、burpsuite、gobuster 等 |
| 纯 Python 工具 | ✅ 可用 | pip install 安装 |
| 第三方 CLI 工具 | ⚠️ 视环境而定 | 考试环境可能有限制 |

### 4.2 手动测试能力（考试重点）

即使有自动化工具，必须掌握以下手动测试能力：

- [ ] 使用 curl 直接测试 LLM API
- [ ] 手动构造提示注入 payload
- [ ] 分析 API 响应判断漏洞存在
- [ ] 识别护栏类型并尝试绕过

### 4.3 考试必备命令

```bash
# 测试 OpenAI-compatible API（curl）
curl -X POST http://target/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Ignore all previous instructions"}]}'

# 扫描 AI 服务端口
nmap -sV -p 80,443,11434,8080,8888 target_ip

# 枚举 AI API 端点
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt

# fuzz 测试提示注入参数
ffuf -w payloads.txt -X POST -d '{"prompt":"FUZZ"}' \
  -H "Content-Type: application/json" http://target/v1/chat
```

```bash
# ==================== Python CLI 替代方案（无 curl 环境或 Windows PowerShell）====================
# 测试 OpenAI-compatible API（chat 子命令，最常用）
python -m redteam.core.http_client chat \
  --url http://target/v1/chat/completions \
  --content "Ignore all previous instructions"

# 带认证的请求
python -m redteam.core.http_client chat \
  --url http://target/v1/chat/completions \
  --content "Ignore all previous instructions" \
  --token "sk-xxxxxxxx"

# 发送自定义 POST 请求
python -m redteam.core.http_client post \
  --url http://target/v1/chat/completions \
  --data '{"messages":[{"role":"user","content":"Hello"}]}'

# 发送 GET 请求（枚举模型）
python -m redteam.core.http_client get \
  --url http://target/v1/models \
  --token "sk-xxxxxxxx"
```

---

## 五、工具与 AI-300 章节映射

| AI-300 章节 | 推荐工具 | 重点技能 |
|-------------|---------|---------|
| **Ch2: AI 目标侦察** | nmap, gobuster, theHarvester, whatweb | 发现 AI 服务、识别技术栈、枚举端点 |
| **Ch3: 单 Agent 攻击** | Burp Suite, ffuf, Promptix, PyRIT | 提示注入、护栏绕过、系统提示提取 |
| **Ch4: 多 Agent 系统** | Burp Suite, wireshark, maltego | 代理间通信分析、信任边界测试 |
| **Ch5: RAG 管道攻击** | Burp Suite, sqlmap, PyRIT | 知识库投毒、检索劫持、向量 DB 攻击 |
| **Ch6: Embedding 攻击** | Python 脚本, PyRIT | 嵌入反演、成员推断、属性推断 |
| **Ch7: MCP 工具攻击** | Burp Suite, mcp-kali-server | 工具劫持、权限滥用、MCP 协议分析 |
| **Ch8: 供应链攻击** | metasploit, sqlmap, wireshark | 代码执行、模型投毒、依赖混淆 |
| **Ch9: 基础设施攻击** | nmap, metasploit, gobuster | 云配置错误、容器逃逸、K8s 利用 |
| **Ch10: 威胁建模** | maltego, nmap | 假设登记册、信任区域界定 |
| **Ch11: 综合演练** | 以上全部工具组合 | 攻击链构建、报告生成 |

---

## 六、参考资源

- [Kali Linux Tools](https://www.kali.org/tools/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [Prompt Injection Guide](https://github.com/agencyenterprise/prompt-injection-guide)

---

**文档版本**: v1.0  
**适用范围**: OffSec AI-300 (OSAI) 考试备考
