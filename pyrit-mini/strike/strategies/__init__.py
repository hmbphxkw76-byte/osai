# -*- coding: utf-8 -*-
"""strike/strategies — 攻击算法参数的**单一访问入口**（plan Wave 4.3）。

背景（plan 1.1.3 / C3 违例）：TAP/PAIR/Crescendo 三套算法的实现参数此前分散在
4 / 2 / 3 处硬编码，且互不一致：

| 算法 | 坐标 | 参数 |
|---|---|---|
| TAP | `escalation_runtime.py`、`progressive_strike.py`、`pair_tap.py`、`dispatcher.py` | depth=3/2/3，width=3/3/5 |
| PAIR | `progressive_strike.py`、`pair_tap.py` | max_iterations=5/10 |
| Crescendo | `escalation_runtime.py`、`progressive_strike.py`、`backdoor.py` | max_backtracks=2 |

同时 `config/defaults.yaml` 早已声明 `tap_tree_width` / `crescendo_max_backtracks`
等键，却**无任何消费者**（C7 断链），形成「YAML 说一套、代码写一套」。

本包把算法参数收敛为：
    config/defaults.yaml（唯一 YAML SSOT，经 C7 链路流入 args）
        → strike.strategies.params（唯一访问器）
            → 各攻击模块

不再新增第二份 `params.yaml`——那只会把「4 处硬编码」换成「2 份 YAML」，
并未治愈 C3。所有算法参数可从 YAML 读取这一验收项因此成立。
"""

from strike.strategies.adversarial import (
    accepted_kwargs,
    build_adversarial_config,
    build_native_attack_kwargs,
)
from strike.strategies.params import (
    algo_params,
    crescendo_params,
    many_shot_params,
    pair_params,
    red_teaming_params,
    tap_params,
)

__all__ = [
    "accepted_kwargs",
    "algo_params",
    "build_adversarial_config",
    "build_native_attack_kwargs",
    "crescendo_params",
    "many_shot_params",
    "pair_params",
    "red_teaming_params",
    "tap_params",
]
