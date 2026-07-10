"""
Profile 构建器 — 将各模块的侦察结果组装为 TargetProfile。
"""

from __future__ import annotations

from recon.schema import (
    TargetProfile, TargetInfo, ProfileMeta, ModelProbeInfo,
    JsSdkInfo, CredentialInfo, WafInfo, RagInfo,
    EndpointType, ApiFormat, Confidence, ReconTool,
)
from recon.probes.model_probe import probe_to_summary


class ProfileBuilder:
    """TargetProfile 组装器。

    负责对各模块产出的原始数据进行清洗、去重、合并和最终组装。
    """

    def __init__(self, profile: TargetProfile):
        self.profile = profile

    def set_target_info(
        self,
        chat_api_url: str = "",
        model_name: str = "",
        endpoint_type: str = "",
        api_format: str = "",
    ):
        """设置目标核心参数。"""
        if chat_api_url:
            self.profile.target.chat_api_url = chat_api_url
        if model_name:
            self.profile.target.model_name = model_name
        if endpoint_type:
            self.profile.target.endpoint_type = endpoint_type
        if api_format:
            self.profile.target.api_format = api_format

    def merge_endpoints(self, endpoints: list, source: str = "unknown"):
        """合并端点列表（去重：同 path + method 的保留首次）。"""
        seen = set()
        for ep in self.profile.api_endpoints:
            seen.add((ep.path, ep.method))

        for ep in endpoints:
            if hasattr(ep, 'path') and hasattr(ep, 'method'):
                key = (ep.path, ep.method)
                if key not in seen:
                    seen.add(key)
                    self.profile.api_endpoints.append(ep)

    def deduplicate(self):
        """对 profile 中的 endpoints 和 dynamic_routes 去重。"""
        # API endpoints
        seen_eps = set()
        unique_eps = []
        for ep in self.profile.api_endpoints:
            key = (ep.path, ep.method)
            if key not in seen_eps:
                seen_eps.add(key)
                unique_eps.append(ep)
        self.profile.api_endpoints = unique_eps

        # Dynamic routes
        seen_routes = set()
        unique_routes = []
        for dr in self.profile.dynamic_routes:
            key = (dr.pattern, dr.method)
            if key not in seen_routes:
                seen_routes.add(key)
                unique_routes.append(dr)
        self.profile.dynamic_routes = unique_routes

    def apply_model_probe(self, probe_result):
        """应用主动模型探测结果到 profile。

        Args:
            probe_result: ModelProbeResult 实例或 dict (probe_to_summary 的输出)
        """
        if probe_result is None:
            return

        # 兼容 dict 和对象
        if isinstance(probe_result, dict):
            mp = probe_result
        else:
            mp = probe_to_summary(probe_result) if hasattr(probe_result, '__dict__') else probe_result

        # 模型名称
        if mp.get("model_name") and not self.profile.target.model_name:
            self.profile.target.model_name = mp["model_name"]
        if mp.get("model_display_name") and not self.profile.target.model_name:
            self.profile.target.model_name = mp["model_display_name"]

        # 端点类型
        if mp.get("endpoint_type") and mp["endpoint_type"] != EndpointType.UNKNOWN.value:
            if self.profile.target.endpoint_type == EndpointType.UNKNOWN.value:
                self.profile.target.endpoint_type = mp["endpoint_type"]

        # 框架
        if mp.get("framework") and mp["framework"] != "unknown":
            self.profile.target.framework = mp["framework"]
        if mp.get("framework_confidence"):
            self.profile.target.framework_confidence = mp["framework_confidence"]

        # 速率限制
        if mp.get("recommended_concurrency"):
            self.profile.rate_limit.recommended_concurrency = mp["recommended_concurrency"]
        if mp.get("recommended_rpm"):
            self.profile.rate_limit.recommended_rpm = mp["recommended_rpm"]
        if mp.get("avg_response_ms"):
            self.profile.rate_limit.avg_response_ms = mp["avg_response_ms"]
        if mp.get("total_429s", 0) > 0:
            self.profile.rate_limit.has_rate_limit = True
            self.profile.rate_limit.total_429s = mp["total_429s"]

        # rate_limit 详情
        rl_detail = mp.get("rate_limit", {})
        if rl_detail:
            self.profile.rate_limit.has_rate_limit = True
            if rl_detail.get("rpm_limit"):
                self.profile.rate_limit.rpm_limit = rl_detail["rpm_limit"]
            if rl_detail.get("tpm_limit"):
                self.profile.rate_limit.tpm_limit = rl_detail["tpm_limit"]

        # 完整 model_probe 信息
        self.profile.model_probe = ModelProbeInfo(
            model_name=mp.get("model_name", ""),
            strategy=mp.get("strategy", ""),
            confidence=mp.get("confidence", 0.0),
            framework=mp.get("framework", "unknown"),
            framework_confidence=mp.get("framework_confidence", "low"),
            endpoint_type=mp.get("endpoint_type", EndpointType.UNKNOWN.value),
            recommended_concurrency=mp.get("recommended_concurrency", 3),
            recommended_rpm=mp.get("recommended_rpm", 30),
            avg_response_ms=mp.get("avg_response_ms", 0.0),
            total_429s=mp.get("total_429s", 0),
            discovered_endpoints=mp.get("discovered_endpoints", []),
            all_attempts=mp.get("all_attempts", []),
            errors=mp.get("errors", []),
        )

    def finalize(self) -> TargetProfile:
        """完成最终组装：去重、排序、补充默认值。"""
        self.deduplicate()

        # 按 category + status 排序
        category_order = {
            "chat": 0, "auth": 1, "models": 2, "tools": 3,
            "agent": 4, "rag": 5, "upload": 6, "search": 7,
            "admin": 8, "debug": 9, "info": 10, "health": 11,
            "stream": 12, "static": 13, "other": 14,
        }
        self.profile.api_endpoints.sort(
            key=lambda ep: (category_order.get(ep.category, 99), ep.status != 200, ep.path)
        )

        # 动态路由按置信度排序
        conf_order = {Confidence.HIGH.value: 0, Confidence.MEDIUM.value: 1, Confidence.LOW.value: 2}
        self.profile.dynamic_routes.sort(
            key=lambda dr: (conf_order.get(dr.confidence, 3), dr.pattern)
        )

        return self.profile
