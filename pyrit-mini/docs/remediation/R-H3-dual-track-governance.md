# R-H3 双轨新增治理记录

> 宪法守卫 INFO 级告警 — 同包内近似模块职责边界声明

生成时间: 2026-09-06
specs 版本: 1.2

---

## 1. arm/converter 模块簇 (3 文件)

| 模块 | 职责 | 边界 |
|------|------|------|
| `converter_chains.py` | 预定义链模式 (l5_optimal, aggressive, stealth) | 仅定义序列模板 |
| `converter_presets.py` | 单 converter 配置预设 | 仅实例化参数 |
| `converter_selector.py` | 运行时动态选择最优 converter | 包含优先级逻辑 + OWASP/Category 过滤 |

**治理策略**: 职责已明确分离。selector 依赖 presets 和 chains，但不替代它们。

---

## 2. arm/seed 模块簇 (3 文件)

| 模块 | 职责 | 边界 |
|------|------|------|
| `seed_auto_expander.py` | 基于 OpenAPI/攻击面自动扩展种子 | 生成新种子 |
| `seed_ranker.py` | 种子管理入口 (load_seeds, prune, UCB rank) | 流程编排 |
| `seed_ranking.py` | 纯排序算法 (_rank_by_asr, update_asr_priors) | 算法实现 |

**治理策略**: seed_ranker.py 是入口；seed_ranking.py 提供算法支撑；auto_expander 是独立扩展能力。

---

## 3. assess/judge 模块簇 (3 文件)

| 模块 | 职责 | 边界 |
|------|------|------|
| `adaptive_dual_judge.py` | 自适应权重双 Judge | 含动态阈值 |
| `dual_judge.py` | 标准双 Judge 交叉验证 | 固定 or_aggregation |
| `judge_manager.py` | Judge 生命周期管理器 | 初始化/调度/缓存 |

**治理策略**: judge_manager 是工厂；dual_judge 和 adaptive_dual_judge 是两种策略实现。

---

## 4. assess/score 模块簇 (2 文件)

| 模块 | 职责 | 边界 |
|------|------|------|
| `scorer.py` | 单评分器封装 (T0/J1/J2/J3) | 单一评分逻辑 |
| `score_pipeline.py` | 级联评分流水线编排 | T0→J1→J2→J3 调度 |

**治理策略**: scorer 是组件；pipeline 是编排器。职责清晰分离。

---

## 5. recon/target 模块簇 (2 文件)

| 模块 | 职责 | 边界 |
|------|------|------|
| `target_builder.py` | HTTPTarget 构造 | 仅构建 |
| `target_router.py` | 目标路由 + 指纹适配 | 路由决策 |

**治理策略**: builder 构造目标；router 决定发送到哪个目标。单向依赖。

---

## 6. strike/escalation 模块簇 (2 文件)

| 模块 | 职责 | 边界 |
|------|------|------|
| `escalation.py` | 主升级逻辑 (check_and_escalate + L1-L4) | 核心编排 |
| `escalation_chain.py` | 链式升级包装 (SequentialAttack 适配) | 高级封装 |

**治理策略**: escalation.py 是核心；escalation_chain.py 是可选的高级包装器。

---

## 治理结论

所有双轨模块簇当前职责边界清晰，无需合并/删除。未来新增相关功能时，应在本记录文件中声明归属模块，避免职责漂移。

---
**签名**: 宪法守卫自动治理 (2026-09-06)
