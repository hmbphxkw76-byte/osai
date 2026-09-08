# 多模态攻击需求评估 (OffSec AI-300)

## 评估结论: **暂不实现**

## 评估依据

### OffSec AI-300 考试范围

AI-300 (Offensive Security AI-300) 考试核心考点:

| 考点 | 权重 | 当前覆盖 | 多模态需求 |
|------|------|----------|------------|
| Prompt Injection | 30% | ✅ 完整 | 否 |
| Training Data Poisoning | 20% | ✅ Seed覆盖 | 否 |
| Model Theft/Extraction | 15% | ✅ Seed覆盖 | 否 |
| Adversarial Examples | 15% | ✅ Converter层 | 否 |
| Supply Chain Attacks | 10% | ✅ CI/CD模块 | 否 |
| Agent Security | 10% | ✅ ASI全覆盖 | 否 |

### 多模态攻击场景分析

| 场景 | AI-300相关性 | 实现复杂度 | 推荐 |
|------|--------------|------------|------|
| 图像对抗样本 | 低 (非考点) | 高 | ❌ |
| 音频注入 | 低 (非考点) | 高 | ❌ |
| 视觉prompt注入 | 中 (边缘考点) | 中 | ⏸️ |
| 跨模态间接注入 | 中 (可能涉及) | 中 | ⏸️ |

### 决策理由

1. **考试导向**: AI-300 不包含多模态攻击考点
2. **资源优先级**: 当前资源应集中于P1/P2缺口
3. **黑盒限制**: 当前框架以HTTP文本API为主
4. **替代方案**: 可通过现有Converter层间接构造跨模态payload

### 未来考虑

当以下条件满足时，重新评估:
- OffSec 发布 AI-300 更新包含多模态考点
- 目标系统明确为多模态模型 (GPT-4V, Gemini Vision)
- PyRIT 原生支持 ImageTarget/AudioTarget

---

*评估时间: 2026-09-08 | 评估人: Red Team Architect*
