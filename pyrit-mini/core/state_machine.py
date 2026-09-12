"""core/state_machine.py — 攻击链状态机 + checkpoint/resume（plan Wave 3 / §3.4）。

把 `StatefulAttackChain` 真正跑起来：

    1. DAG 调度：每轮取 `ready_steps()`（前置完成 + 输入齐备）执行
    2. 状态推进：步骤产出写入 `ChainState.acquired`，供下游步骤消费
    3. checkpoint：每步落盘，支持 `--resume` 从最后一个完成步骤继续（真语义）
    4. 失败留痕：失败写入 `failed_steps`，`continue_on_step_failure` 控制是否继续

`ChainState` 小步推进 + 每步快照，支持步骤级回滚（§8 风险「状态污染」）。

Usage:
    sm = ChainStateMachine(chain, checkpoint_path=out / "attack_chain.json")
    result = await sm.run(executor=my_step_executor)

Academic basis:
    - Gamma et al., Design Patterns (1994): State 模式
    - Chao et al. (arXiv:2310.08419) PAIR: 多轮状态推进
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

# 步骤执行器签名：接收 (step, state)，返回产出物 dict（key 来自 step.produces）
StepExecutor = Callable[[Any, Any], Awaitable[dict[str, Any]]]


@dataclass
class ChainRunResult:
    """链执行结果。"""

    chain_id: str = ""
    total_steps: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    acquired_keys: list[str] = field(default_factory=list)
    failures: list[dict[str, str]] = field(default_factory=list)
    resumed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "total_steps": self.total_steps,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "skipped": self.skipped,
            "acquired_keys": list(self.acquired_keys),
            "failures": list(self.failures),
            "resumed": self.resumed,
        }


class ChainStateMachine:
    """攻击链执行状态机（DAG 调度 + checkpoint/resume）。"""

    def __init__(
        self,
        chain: Any,
        *,
        checkpoint_path: Path | str | None = None,
        checkpoint_enabled: bool = True,
        continue_on_step_failure: bool = True,
        max_steps: int = 64,
    ) -> None:
        self.chain = chain
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else None
        self.checkpoint_enabled = checkpoint_enabled and self.checkpoint_path is not None
        self.continue_on_step_failure = continue_on_step_failure
        self.max_steps = max(1, int(max_steps))

    # ------------------------------------------------------------------
    # 主循环
    # ------------------------------------------------------------------
    async def run(self, executor: StepExecutor) -> ChainRunResult:
        """执行攻击链。"""
        chain = self.chain
        state = chain.state
        result = ChainRunResult(chain_id=str(state.chain_id), total_steps=len(chain.steps))

        if self.checkpoint_enabled and self._try_resume():
            result.resumed = True
            done, total = chain.progress()
            logger.info("[Chain] 从 checkpoint 恢复：已完成 %d/%d 步", done, total)

        executed = 0
        while executed < self.max_steps:
            pending = [s for s in chain.ready_steps() if state.status.get(s.id) in (None, "pending")]
            if not pending:
                break

            for step in pending:
                if state.status.get(step.id) in ("succeeded", "skipped"):
                    continue
                state.mark(step.id, "running")
                state.visit(step.component_key)
                try:
                    produced = await executor(step, state) or {}
                except asyncio.CancelledError:
                    state.mark(step.id, "pending")  # 回滚为待执行，支持 resume
                    self._checkpoint()
                    raise
                except Exception as e:
                    # 反静默：失败必须有 reason（禁止 except: pass）
                    reason = f"{type(e).__name__}: {e}"
                    state.record_failure(step.id, reason)
                    result.failed += 1
                    result.failures.append({"step_id": step.id, "reason": reason})
                    logger.warning("[Chain] 步骤 %s 失败: %s", step.id, reason)
                    self._checkpoint()
                    if not self.continue_on_step_failure:
                        return self._finalize(result)
                    continue

                # 成功：写入 acquired（下游消费）
                for key in step.produces:
                    if key in produced:
                        state.produce(key, produced[key])
                state.budget_spent += int(step.budget_cost or 0)
                state.mark(step.id, "succeeded")
                state.step_index += 1
                result.succeeded += 1
                executed += 1
                logger.info("[Chain] 步骤 %s 完成（产出: %s）", step.id, ", ".join(step.produces) or "(无)")
                self._checkpoint()

            if not [s for s in chain.ready_steps() if state.status.get(s.id) in (None, "pending")]:
                break

        return self._finalize(result)

    def _finalize(self, result: ChainRunResult) -> ChainRunResult:
        state = self.chain.state
        result.skipped = sum(1 for s in self.chain.steps if state.status.get(s.id) == "skipped")
        result.acquired_keys = sorted(state.acquired.keys())
        self._checkpoint()
        return result

    # ------------------------------------------------------------------
    # checkpoint / resume
    # ------------------------------------------------------------------
    def _checkpoint(self) -> None:
        if not self.checkpoint_enabled or self.checkpoint_path is None:
            return
        try:
            self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"schema_version": "1.0", "chain": self.chain.to_dict()}
            self.checkpoint_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as e:
            logger.warning("[Chain] checkpoint 落盘失败（不阻塞）: %s", e)

    def _try_resume(self) -> bool:
        """从 checkpoint 恢复链状态；无文件或损坏时返回 False（IA-6：不崩溃）。"""
        if self.checkpoint_path is None or not self.checkpoint_path.is_file():
            return False
        try:
            raw = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            payload = raw.get("chain") if isinstance(raw, dict) else None
            if not isinstance(payload, dict):
                return False
            restored = self.chain.__class__.from_dict(payload)
            # 只恢复状态，不覆盖步骤定义（步骤可能因识别结果变化而更新）
            self.chain.state = restored.state
            logger.info(
                "[Chain] 已恢复 checkpoint: chain_id=%s, 已完成 %d/%d",
                restored.state.chain_id,
                *self.chain.progress(),
            )
            return True
        except Exception as e:
            logger.warning("[Chain] checkpoint 恢复失败，从零开始: %s", e)
            return False

    # ------------------------------------------------------------------
    # 回滚（步骤级）
    # ------------------------------------------------------------------
    def rollback_step(self, step_id: str) -> bool:
        """把单个步骤回滚为 pending，并清理其产出物（步骤级回滚，防状态污染）。"""
        step = self.chain.step(step_id)
        if step is None:
            return False
        self.chain.state.status.pop(step_id, None)
        self.chain.state.failed_steps = [f for f in self.chain.state.failed_steps if f.step_id != step_id]
        for key in step.produces:
            self.chain.state.acquired.pop(key, None)
        self._checkpoint()
        logger.info("[Chain] 步骤 %s 已回滚", step_id)
        return True
