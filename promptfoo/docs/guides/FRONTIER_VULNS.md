# 前沿漏洞类型

> AI/LLM 安全领域的前沿漏洞类型速查
> 覆盖 OWASP LLM Top 10、Agentic AI、MCP、A2A 等新兴威胁

---

## 一、OWASP LLM Top 10 (2025)

| 编号 | 漏洞类型 | 说明 | 对应插件 |
|:---:|---------|------|---------|
| LLM01 | 提示注入 | 直接/间接操纵模型输入 | `indirect-prompt-injection`, `prompt-extraction` |
| LLM02 | 不安全输出处理 | LLM 输出未净化导致下游漏洞 | `harmful:*` |
| LLM03 | 训练数据投毒 | 训练数据被注入恶意内容 | `rag-poisoning`, `bias` |
| LLM04 | 模型拒绝服务 | 耗尽模型资源 | `reasoning-dos`, `divergent-repetition` |
| LLM05 | 供应链漏洞 | 第三方组件/模型风险 | `coding-agent:automation-poisoning` |
| LLM06 | 敏感信息泄露 | PII、密钥、系统信息泄露 | `pii:*`, `data-exfil`, `prompt-extraction` |
| LLM07 | 不安全插件设计 | 插件缺乏输入验证 | `shell-injection`, `ssrf` |
| LLM08 | 过度代理 | Agent 执行超出授权的操作 | `excessive-agency`, `goal-misalignment` |
| LLM09 | 过度依赖 | 盲信 LLM 输出导致决策错误 | `hallucination` |
| LLM10 | 模型盗窃 | 窃取模型权重或能力 | `prompt-extraction` |

---

## 二、Agentic AI Top 10

| 编号 | 漏洞类型 | 说明 | 对应插件 |
|:---:|---------|------|---------|
| ASI01 | Agent 记忆投毒 | 污染 Agent 的记忆/上下文 | `agentic:memory-poisoning` |
| ASI02 | 工具发现滥用 | 枚举并滥用可用工具 | `tool-discovery` |
| ASI03 | 目标劫持 | 偏离原始目标 | `goal-misalignment` |
| ASI04 | 权限提升 | BOLA/BFLA/RBAC 绕过 | `bola`, `bfla`, `rbac` |
| ASI05 | 跨 Agent 注入 | Agent 间通信被注入 | `indirect-prompt-injection` |
| ASI06 | 信任链污染 | Agent 信任链被破坏 | `hijacking` |
| ASI07 | 系统提示覆盖 | 覆盖系统指令 | `system-prompt-override` |
| ASI08 | 过度自主 | Agent 自主性过强 | `excessive-agency` |
| ASI09 | 数据外泄 | 通过工具泄露数据 | `data-exfil` |
| ASI10 | 沙箱逃逸 | 逃逸执行沙箱 | `coding-agent:sandbox-escape` |

---

## 三、MCP 协议漏洞

| 漏洞 | 说明 | 攻击方式 |
|------|------|---------|
| 工具描述投毒 | 在工具描述中注入恶意指令 | 修改 tool description 诱导 Agent |
| 工具遮蔽 | 恶意工具覆盖合法工具 | 同名工具优先级劫持 |
| 侧信道泄露 | 通过工具输出泄露数据 | 编码数据藏在工具返回值 |
| 跨服务器 SSRF | 利用工具发起 SSRF | 工具访问内网 `169.254.169.254` |
| 能力绕过 | MCP 服务器能力缺失 | 直接调用受限工具 |

---

## 四、A2A 协议漏洞

| 漏洞 | 说明 | 攻击方式 |
|------|------|---------|
| Agent Card 伪造 | 伪造 Agent 身份卡片 | 注册恶意 Agent Card |
| 任务委托投毒 | 污染跨 Agent 任务委托 | 注入恶意任务参数 |
| 信任链污染 | 破坏 Agent 间信任 | 中间人篡改消息 |
| 消息注入 | Agent 间消息被注入 | 间接提示注入跨 Agent |

---

## 五、新兴威胁

### 5.1 多模态攻击

| 威胁 | 说明 |
|------|------|
| 视觉提示注入 | 图片中嵌入对抗性指令 |
| OCR 绕过 | 利用 OCR 识别绕过文本过滤 |
| 对抗性图像 | 扰动图像误导视觉模型 |
| 多模态幻觉 | 图文不一致导致幻觉 |

### 5.2 编码助手攻击

| 威胁 | 说明 |
|------|------|
| 沙箱读写逃逸 | 逃逸代码执行沙箱 |
| 凭据窃取 | 窃取环境变量中的密钥 |
| CI/CD 投毒 | 在生成代码中注入恶意流水线 |
| 仓库级注入 | 在代码仓库中植入提示注入 |
| 隐写术外泄 | 用隐写术将数据藏在图片中泄露 |

### 5.3 嵌入与向量库攻击

| 威胁 | 说明 |
|------|------|
| 向量投毒 | 污染向量数据库 | 
| 嵌入反转 | 从嵌入向量反推原始文本 |
| 语义操纵 | 操纵语义空间影响检索 |
| 近似搜索利用 | 利用 ANN 搜索的近似性绕过 |

### 5.4 供应链攻击

| 威胁 | 说明 |
|------|------|
| 模型投毒 | 后训练阶段注入后门 |
| 行为回归 | 模型升级后安全对齐退化 |
| 后门触发 | 特定触发词激活恶意行为 |
| 依赖投毒 | 第三方库/模型被投毒 |

---

## 六、漏洞严重级别

| 级别 | 定义 | 响应时间 | 示例 |
|:---:|------|---------|------|
| 🔴 Critical | 可直接获取系统控制权 | 立即 | RCE、完全越狱、批量 PII 泄露 |
| 🟠 High | 可获取敏感信息或越权 | 24h | PII 泄露、BOLA 越权访问 |
| 🟡 Medium | 部分功能受影响 | 1周 | 部分绕过、非敏感信息泄露 |
| 🟢 Low | 影响较小 | 按计划 | 输出格式异常、轻微幻觉 |
| ⚪ Info | 仅作信息记录 | - | 最佳实践建议、风格问题 |

---

## 七、攻击策略对照

| 策略 | 适用漏洞类型 | 效果 |
|------|------------|------|
| `basic` | 所有 | 原始测试，建立基线 |
| `jailbreak` | LLM01, 安全对齐 | LLM 迭代越狱 |
| `jailbreak:composite` | LLM01 | 组合多种越狱技术 |
| `jailbreak:tree` | LLM01 | 树形探索越狱路径 |
| `base64` | LLM01, 过滤绕过 | Base64 编码绕过 |
| `leetspeak` | LLM01, 过滤绕过 | Leetspeak 编码绕过 |
| `crescendo` | LLM01, ASI03 | 渐进式攻击 |
| `multi-turn` | ASI01, ASI05 | 多轮对话累积攻击 |
| `best-of-n` | LLM01 | 多次尝试取最优 |
| `retry` | 所有 | 重试失败用例 |

---

## 相关文档

- [架构说明](ARCHITECTURE.md) - 项目整体架构
- [Payload 加载机制](PAYLOAD_LOADING.md) - 攻击 payload 如何注入
- [渗透模式指南](PENETRATING_MODE_GUIDE.md) - 测试模式选择
- [开发规范 - YAML 模式](../dev-standards/yaml-patterns.md) - 红队配置规范
