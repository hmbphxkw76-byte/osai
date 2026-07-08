# PyRIT 文档索引

> PyRIT 红队渗透测试框架文档，按角色和场景组织导航。

---

## 快速开始

| 文档 | 说明 | 目标读者 |
|------|------|----------|
| [快速入门](getting-started.md) | 一键命令速查 + 核心参数表 + 执行流程 | 所有人 |
| [一、侦察阶段](reconnaissance-guide.md) | 端点枚举 → 模型识别 → 架构探测 → 部署定位 | 红队操作员 |
| [二、攻击阶段](attack-scenarios.md) | 三种认证场景的完整攻击命令和策略 | 红队操作员 |
| [三、攻击后研判](post-attack-analysis.md) | 战报解读 → 研判工作流 → 渗透深化 → 归档 | 红队操作员 |
| [四、端到端管线](end-to-end-pipeline.md) | 全自动侦察→攻击→评分→报告 一键命令 | 红队操作员 |
| [五、自适应引擎](adaptive-engine.md) | 动态组合(300+) + Bandit调度 + 厂商载荷 | 红队操作员 |
| [按目标架构攻击手册](PER_TARGET_ATTACK_GUIDE.md) | 覆盖 7 种目标架构，对齐 OFF SEC AI-300 | 红队操作员 |
| [渗透模式指南](PENETRATING_MODE_GUIDE.md) | YAML 模板驱动的渗透模式 | 红队操作员 |

---

## 架构与原理

| 文档 | 说明 | 目标读者 |
|------|------|----------|
| [系统架构](ARCHITECTURE.md) | PyRIT 整体架构设计 | 开发者/架构师 |
| [Payload 加载机制](PAYLOAD_LOADING.md) | 载荷加载与变量注入机制 | 开发者 |
| [前沿漏洞追踪](FRONTIER_VULNS.md) | 前沿漏洞与攻击技术说明 | 开发者/安全研究员 |

---

## 开发规范

| 文档 | 说明 | 目标读者 |
|------|------|----------|
| [contributing/](../contributing/) | 5 份研发规范：架构设计、模块拆分、配置管理、YAML 定义、命名规范 | 贡献者 |

---

## 阅读路径建议

### 首次使用的红队操作员
```
getting-started.md → reconnaissance-guide.md → attack-scenarios.md
```

### 需要提交渗透报告
```
getting-started.md → post-attack-analysis.md → end-to-end-pipeline.md
```

### 高价值目标深挖
```
getting-started.md → attack-scenarios.md → adaptive-engine.md
```

### 新人 Onboarding 贡献代码
```
ARCHITECTURE.md → PAYLOAD_LOADING.md → [contributing/](../contributing/)
```

---

> **历史说明**：`PYRIT_COMMAND_REFERENCE.md` 已按渗透流程拆分为上述 6 个文件（快速入门 + 侦察 + 攻击 + 研判 + 管线 + 引擎），原文件不再维护。
