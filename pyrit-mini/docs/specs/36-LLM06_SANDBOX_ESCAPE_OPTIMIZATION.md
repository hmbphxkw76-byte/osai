# LLM06 Sandbox Escape 补充优化建议

## 当前状态

| 维度 | 现状 |
|------|------|
| Seed文件 | T3_LLM06_escape_sandbox.prompt (6个种子, Tier 3) |
| ASR | <20% (实验性) |
| 覆盖维度 | 情感操纵、渐进暴露、编码伪装、角色扮演、假设场景、代码形式 |

## 优化建议 (优先级排序)

### P1: 提升ASR (目标: Tier 2, 20-50%)

#### 1.1 新增种子向量

```yaml
# 建议新增攻击向量 (参考学术来源):

# R1: 上下文窗口溢出 (arXiv:2402.05124)
- category: context_window_overflow
  technique: 触发超长上下文处理异常
  expected_asr: 25-35%

# R2: 时间延迟攻击 (arXiv:2401.06595)
- category: timing_side_channel
  technique: 通过响应时间差异探测系统状态
  expected_asr: 20-30%

# R3: 递归自引用 (arXiv:2402.12109)
- category: recursive_self_reference
  technique: 构造自引用prompt导致模型陷入循环
  expected_asr: 22-32%

# R4: 多语言混合编码 (arXiv:2310.07174)
- category: multilingual_encoding_mix
  technique: 混合使用低资源语言绕过安全过滤
  expected_asr: 30-40%

# R5: 假设角色锚定 (arXiv:2406.18112)
- category: hypothetical_role_anchoring
  technique: 基于SkeletonKey的假设场景深化
  expected_asr: 35-45%
```

#### 1.2 技术集成优化

```python
# 建议集成至 strike/executor.py L1层
# 在 CoT Hijack 后增加 sandbox_escape_vector

async def _run_sandbox_escape_enhanced(ctx, objectives):
    """
    LLM06增强版 - 结合多种向量
    """
    # 1. 基础向量 (现有6个)
    # 2. 新增: 自适应选择器 (基于目标指纹)
    # 3. 新增: 失败自动切换 (ASR <阈值时切换向量)
```

### P2: 工程化改进

#### 2.1 自适应选择器

```python
# 根据目标类型自动选择攻击向量
SANDBOX_ESCAPE_VECTORS = {
    "code_generation_model": ["code_form_evasion", "recursive_self_reference"],
    "chat_model": ["emotional_manipulation", "persona_injection"],
    "multilingual_model": ["multilingual_encoding_mix"],
    "api_endpoint": ["context_window_overflow", "timing_side_channel"],
}
```

#### 2.2 失败回退机制

```python
# 实现自动降级和重试
# 如果 emotional_manipulation 失败, 自动切换到 hypothetical_opt_out
```

### P3: 升级路径

```
当前: Tier 3 (实验性, <20%)
  ↓
Phase 1: 新增 5 个种子向量 (ASR 25-35%)
  ↓
Phase 2: 集成至 L1 升级链 (与 CoT Hijack 协同)
  ↓
Phase 3: 自适应选择器 + ASR历史排序 (ASR 35-45%)
  ↓
目标: Tier 2 (中等, 20-50%)
```

## 实施计划

| 阶段 | 任务 | 预估工作量 | 预期ASR提升 |
|------|------|------------|-------------|
| Phase 1 | 新增5个种子向量 | 2h | +10-15% |
| Phase 2 | 集成至L1升级链 | 3h | +5-10% |
| Phase 3 | 自适应选择器 | 4h | +5-10% |

## 学术参考

| 论文 | arXiv ID | 应用场景 |
|------|----------|----------|
| Many-Shot Jailbreaking | 2402.05124 | 上下文窗口溢出 |
| WildTeaming | 2401.06595 | 时间侧信道 |
| Crescendo | 2402.12109 | 递归自引用 |
| Multilingual Attacks | 2310.07174 | 多语言混合编码 |
| SkeletonKey | 2406.18112 | 假设角色锚定 |

---

*文档版本: v1.0 | 创建日期: 2026-09-08*
