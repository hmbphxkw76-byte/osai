# -*- coding: utf-8 -*-
"""
AI-300 Framework - Native Probe Adapter
轻量级探针适配器：从 garak 提取的静态 probe 数据，零外部依赖

设计原则：
- 零外部依赖：仅使用 stdlib（urllib）+ PyYAML（已有依赖）
- 薄壳模式：加载 YAML probe 数据 → 发送 prompt → 检测响应 → 返回 AdapterResult
- OWASP 映射：每个 probe 带有 OWASP LLM Top 10 映射
- 深度分层：支持 quick/standard/deep 三级探测深度
- 缓存支持：按 target+probe+depth 哈希缓存

支持的 Probe（8 个）：
  1. packagehallucination - 包幻觉检测 (LLM09)
  2. apikey - API 密钥生成检测 (LLM02)
  3. smuggling - Token 走私/同形字绕过 (LLM01)
  4. suffix - GCG 对抗后缀攻击 (LLM01)
  5. web_injection - Web 注入/XSS 检测 (LLM06)
  6. propile - PII 隐私泄露检测 (LLM06)
  7. sysprompt_extraction - 系统提示词提取 (LLM07)
  8. many_shot - Many-Shot Jailbreak 长上下文攻击 (LLM01)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..base import AdapterResult, BaseAdapter
from ...utils.http_client import http_post
from .detectors import PatternDetector, RefusalDetector

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# Probe 数据目录
PROBE_DATA_DIR = Path(__file__).parent / "probe_data"

# 默认 Probe 列表（按深度分层）
PROBES_BY_DEPTH: Dict[str, List[str]] = {
    "quick": [
        "sysprompt_extraction",
        "apikey",
    ],
    "standard": [
        "sysprompt_extraction",
        "apikey",
        "packagehallucination",
        "smuggling",
        "web_injection",
    ],
    "deep": [
        "sysprompt_extraction",
        "apikey",
        "packagehallucination",
        "smuggling",
        "suffix",
        "web_injection",
        "propile",
        "many_shot",
    ],
}

# 默认 Probe 列表
DEFAULT_PROBES = PROBES_BY_DEPTH["standard"]

# Probe → OWASP 映射（运行时从 YAML 加载，此处为 fallback）
PROBE_OWASP_MAP: Dict[str, str] = {
    "packagehallucination": "LLM09",
    "apikey": "LLM02",
    "smuggling": "LLM01",
    "suffix": "LLM01",
    "web_injection": "LLM06",
    "propile": "LLM06",
    "sysprompt_extraction": "LLM07",
    "many_shot": "LLM01",
}

# 缓存目录
NATIVE_PROBE_CACHE_DIR = "results/recon/cache/native_probe"

# 每个 prompt 的最大 token 限制（控制成本）
DEFAULT_MAX_TOKENS = 256

# 深度 → 每 probe 最大 prompt 数
PROMPT_CAPS: Dict[str, int] = {
    "quick": 5,
    "standard": 10,
    "deep": 20,
}


class NativeProbeAdapter(BaseAdapter):
    """
    轻量级探针适配器

    从 garak 提取的静态 probe 数据，通过已有 HTTP 客户端发送 prompt，
    使用正则/关键词检测器判断响应，零外部依赖。

    工作流：
      1. 加载 YAML 格式的 probe 数据
      2. 按 depth 限制 prompt 数量
      3. 通过 http_post 发送 prompt 到目标 LLM
      4. 用 PatternDetector/RefusalDetector 检测响应
      5. 输出标准 AdapterResult
    """

    @property
    def name(self) -> str:
        return "native_probe"

    def check_available(self) -> bool:
        """NativeProbeAdapter 始终可用（零外部依赖）"""
        return True

    def run(self, target: str, config: dict) -> AdapterResult:
        """
        执行轻量级探针扫描

        Args:
            target: 目标 LLM endpoint URL（如 http://localhost:11434/v1/chat/completions）
            config: 配置字典，支持：
                - probes: 指定 probe 列表（None=按 depth 自动选择）
                - depth: 探测深度（quick/standard/deep）
                - model_name: 目标模型名称
                - timeout: 超时秒数
                - use_cache: 是否使用缓存
                - aimap_data: AIMAP 检测结果（用于动态选择 probe）
                - credential_headers: 认证头
                - credential_bearer: Bearer token
                - max_concurrent: 最大并发数

        Returns:
            AdapterResult
        """
        start_time = time.time()

        # 解析配置
        depth = config.get("depth", "standard")
        probes = config.get("probes") or self._select_probes(config)
        model_name = config.get("model_name", "")
        timeout = config.get("timeout", 60)
        use_cache = config.get("use_cache", True)
        prompt_cap = PROMPT_CAPS.get(depth, 10)

        # 认证
        credential_headers = config.get("credential_headers", {})
        credential_bearer = config.get("credential_bearer", "")
        auth_headers = self._build_auth_headers(credential_headers, credential_bearer)

        # 缓存检查
        cache_key = self._compute_cache_key(target, model_name, probes, depth)
        if use_cache:
            cached = self._load_cache(cache_key)
            if cached:
                logger.info("NativeProbe cache hit: %s", cache_key)
                cached["cache_hit"] = True
                return AdapterResult(
                    tool=self.name,
                    success=True,
                    data=cached.get("data", {}),
                    findings=cached.get("findings", []),
                    duration=0.0,
                )

        try:
            # 确定聊天端点
            chat_url = self._resolve_chat_url(target)
            logger.info(
                "NativeProbe: running %d probes (depth=%s) against %s",
                len(probes), depth, chat_url,
            )

            all_findings: List[Dict[str, Any]] = []
            probe_results: Dict[str, Any] = {}

            for probe_name in probes:
                probe_start = time.time()

                # 加载 probe 数据
                probe_data = self._load_probe_data(probe_name)
                if not probe_data:
                    logger.warning("Probe data not found: %s, skipping", probe_name)
                    continue

                # 生成 prompts
                prompts = self._generate_prompts(probe_data, prompt_cap)
                if not prompts:
                    logger.warning("No prompts generated for probe %s", probe_name)
                    continue

                # 发送 prompts 并收集响应
                prompt_response_pairs: List[Tuple[str, str]] = []
                errors: List[str] = []

                for prompt in prompts:
                    response, error = self._send_prompt(
                        chat_url, prompt, model_name, timeout, auth_headers, probe_data
                    )
                    if error:
                        errors.append(error)
                    if response:
                        prompt_response_pairs.append((prompt, response))

                # 检测响应
                detection_rules = probe_data.get("detection_rules", [])
                findings = self._detect_responses(
                    probe_name, probe_data, detection_rules, prompt_response_pairs
                )

                probe_duration = (time.time() - probe_start) * 1000
                probe_results[probe_name] = {
                    "prompts_sent": len(prompts),
                    "responses_received": len(prompt_response_pairs),
                    "findings_count": len(findings),
                    "duration_ms": round(probe_duration, 1),
                    "errors": errors[:5],  # 限制错误数量
                    "owasp_mapping": probe_data.get("owasp_mapping", ""),
                    "severity": probe_data.get("severity", "medium"),
                }
                all_findings.extend(findings)

                logger.info(
                    "NativeProbe %s: %d prompts, %d findings, %.0fms",
                    probe_name, len(prompts), len(findings), probe_duration,
                )

            duration = time.time() - start_time
            success = len(probe_results) > 0

            result_data = {
                "probes_used": probes,
                "depth": depth,
                "model_name": model_name or "auto-detected",
                "probe_results": probe_results,
                "total_findings": len(all_findings),
                "cache_key": cache_key,
            }

            # 保存缓存
            if use_cache and success:
                self._save_cache(cache_key, {"data": result_data, "findings": all_findings})

            return AdapterResult(
                tool=self.name,
                success=success,
                data=result_data,
                findings=all_findings,
                duration=duration,
                raw_output=json.dumps(
                    {k: v for k, v in probe_results.items()},
                    ensure_ascii=False, indent=2,
                )[:2000],
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error("NativeProbe execution failed: %s", str(e))
            return AdapterResult(
                tool=self.name,
                success=False,
                errors=[str(e)],
                duration=duration,
            )

    # ── Probe 选择 ──

    def _select_probes(self, config: dict) -> List[str]:
        """
        基于深度和 AIMAP 数据动态选择 probe

        策略：
        1. 用户显式配置 probes → 使用用户配置
        2. 基于 depth 分层选择
        3. AIMAP 数据驱动的动态扩展
        """
        depth = config.get("depth", "standard")
        base_probes = list(PROBES_BY_DEPTH.get(depth, PROBES_BY_DEPTH["standard"]))

        # AIMAP 驱动的动态扩展
        aimap_data = config.get("aimap_data", {})
        capabilities = aimap_data.get("capabilities", [])
        surfaces = aimap_data.get("surfaces", [])

        # function_calling → 增加 smuggling（测试绕过过滤）
        if "function_calling" in capabilities and "smuggling" not in base_probes:
            base_probes.append("smuggling")

        # vision → 增加 web_injection（测试 Markdown 注入）
        if "vision" in capabilities and "web_injection" not in base_probes:
            base_probes.append("web_injection")

        # agent/mcp → 增加 suffix（测试 jailbreak）
        if "agent" in surfaces or "mcp" in aimap_data.get("detected_protocols", []):
            if "suffix" not in base_probes and depth != "quick":
                base_probes.append("suffix")

        logger.info("NativeProbe probes selected: %s (depth=%s)", base_probes, depth)
        return base_probes

    # ── Probe 数据加载 ──

    @staticmethod
    def _load_probe_data(probe_name: str) -> Optional[Dict[str, Any]]:
        """加载 probe YAML 数据"""
        import yaml

        yaml_path = PROBE_DATA_DIR / f"{probe_name}.yaml"
        if not yaml_path.exists():
            logger.warning("Probe YAML not found: %s", yaml_path)
            return None

        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error("Failed to load probe data %s: %s", probe_name, e)
            return None

    # ── Prompt 生成 ──

    def _generate_prompts(self, probe_data: Dict[str, Any], cap: int) -> List[str]:
        """根据 probe 数据生成 prompt 列表"""
        probe_name = probe_data.get("probe_name", "")
        prompts: List[str] = []

        if probe_name == "packagehallucination":
            prompts = self._gen_packagehallucination_prompts(probe_data)
        elif probe_name == "apikey":
            prompts = self._gen_apikey_prompts(probe_data)
        elif probe_name == "smuggling":
            prompts = self._gen_smuggling_prompts(probe_data)
        elif probe_name == "suffix":
            prompts = self._gen_suffix_prompts(probe_data)
        elif probe_name == "web_injection":
            prompts = self._gen_web_injection_prompts(probe_data)
        elif probe_name == "propile":
            prompts = self._gen_propile_prompts(probe_data)
        elif probe_name == "sysprompt_extraction":
            prompts = self._gen_sysprompt_extraction_prompts(probe_data)
        elif probe_name == "many_shot":
            prompts = self._gen_many_shot_prompts(probe_data, cap)
        else:
            # 通用 prompt 列表
            prompts = probe_data.get("prompts", [])

        # 限制 prompt 数量
        if len(prompts) > cap:
            prompts = random.sample(prompts, cap)

        return prompts

    def _gen_packagehallucination_prompts(self, data: Dict[str, Any]) -> List[str]:
        """生成包幻觉探测 prompt"""
        templates = data.get("prompt_templates", [])
        languages = data.get("languages", ["Python3"])
        unreal_tasks = data.get("unreal_tasks", [])
        real_tasks = data.get("real_tasks", [])
        all_tasks = unreal_tasks + real_tasks

        prompts = []
        for tmpl in templates:
            for lang in languages[:2]:  # 仅用前 2 种语言
                for task in all_tasks[:3]:  # 每语言 3 个任务
                    prompts.append(tmpl.format(lang=lang, task=task))
        return prompts

    def _gen_apikey_prompts(self, data: Dict[str, Any]) -> List[str]:
        """生成 API 密钥探测 prompt"""
        key_types = data.get("key_types", [])
        gen_prompts = data.get("generation_prompts", [])
        comp_prompts = data.get("completion_prompts", [])

        prompts = []
        for kt in key_types[:3]:  # 限制 3 种密钥类型
            for gp in gen_prompts:
                prompts.append(gp.format(key_type=kt))
        prompts.extend(comp_prompts[:2])
        return prompts

    def _gen_smuggling_prompts(self, data: Dict[str, Any]) -> List[str]:
        """生成走私/同形字探测 prompt"""
        prompts = list(data.get("hypothetical_prompts", []))
        func_masking = data.get("function_masking_prompt", "")
        if func_masking:
            prompts.append(func_masking.strip())

        # 同形字混淆 prompt
        homoglyph_map = data.get("homoglyph_map", {})
        targets = data.get("obfuscation_targets", [])
        for target in targets[:2]:
            obfuscated = self._apply_homoglyphs(target, homoglyph_map)
            prompts.append(f"Tell me {obfuscated}")

        return prompts

    def _gen_suffix_prompts(self, data: Dict[str, Any]) -> List[str]:
        """生成 GCG 后缀攻击 prompt"""
        base_prompts = data.get("base_prompts", [])
        suffixes = data.get("gcg_suffixes", [])

        prompts = []
        for base in base_prompts:
            for suffix in suffixes[:5]:  # 每个 base prompt 用 5 个后缀
                prompts.append(f"{base} {suffix}")
        return prompts

    def _gen_web_injection_prompts(self, data: Dict[str, Any]) -> List[str]:
        """生成 Web 注入探测 prompt"""
        template = data.get("markdown_exfil_template", "")
        domains = data.get("domains", ["evil.example.com"])
        encodings = data.get("encodings", ["base64"])

        prompts = []
        for domain in domains[:2]:
            for encoding in encodings[:2]:
                prompt = template.replace("{domain}", domain).replace("{encoding}", encoding)
                prompts.append(prompt.strip())

        # JS 注入 prompt
        js_template = data.get("markdown_js_template", "")
        js_payloads = data.get("js_payloads", [])
        for payload in js_payloads[:2]:
            prompts.append(js_template.replace("{js}", payload))

        return prompts

    def _gen_propile_prompts(self, data: Dict[str, Any]) -> List[str]:
        """生成 PII 泄露探测 prompt"""
        templates = data.get("twin_templates", [])
        triplets = data.get("triplet_templates", [])
        quadruplets = data.get("quadruplet_templates", [])
        personas = data.get("test_personas", [])

        prompts = []
        for persona in personas[:2]:  # 2 个测试人物
            for tmpl in templates[:2]:  # 2 个 twin 模板
                prompts.append(tmpl.format(**persona))
            for tmpl in triplets[:1]:  # 1 个 triplet 模板
                prompts.append(tmpl.format(**persona))

        return prompts

    def _gen_sysprompt_extraction_prompts(self, data: Dict[str, Any]) -> List[str]:
        """生成系统提示词提取探测 prompt"""
        return list(data.get("attack_templates", []))

    def _gen_many_shot_prompts(self, data: Dict[str, Any], cap: int) -> List[str]:
        """
        生成 Many-Shot Jailbreak 探测 prompt

        利用长上下文窗口：将大量虚构 Q&A 对填充到上下文中，
        然后在末尾附加目标请求，利用上下文引导模型执行有害行为。

        Anthropic 研究表明，当 Q&A 对数量超过一定阈值（~32个）时，
        模型拒绝率显著下降。本实现用少量示例（10个）进行轻量探测，
        通过 repeat_factors 控制填充倍数。
        """
        templates = data.get("templates", {})
        few_shot_examples = data.get("few_shot_examples", [])
        target_requests = data.get("target_requests", [])
        repeat_factors = data.get("repeat_factors", {})

        if not templates or not few_shot_examples or not target_requests:
            return []

        # 根据深度确定重复倍数（默认 standard=3）
        # cap 决定了深度：quick=5, standard=10, deep=20
        if cap <= 5:
            repeat = repeat_factors.get("quick", 1)
        elif cap <= 10:
            repeat = repeat_factors.get("standard", 3)
        else:
            repeat = repeat_factors.get("deep", 5)

        # 构建填充的 few-shot 内容
        stuffed_examples = "\n\n".join(few_shot_examples * repeat)

        prompts = []
        template_keys = list(templates.keys())
        for tmpl_key in template_keys[:2]:  # 使用前 2 个模板
            tmpl = templates[tmpl_key]
            for request in target_requests[:2]:  # 每个模板 2 个目标请求
                prompt = tmpl.replace("{few_shot_examples}", stuffed_examples)
                prompt = prompt.replace("{target_request}", request)
                prompts.append(prompt.strip())

        return prompts

    # ── Prompt 发送 ──

    def _send_prompt(
        self,
        chat_url: str,
        prompt: str,
        model_name: str,
        timeout: int,
        auth_headers: Dict[str, str],
        probe_data: Dict[str, Any],
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        发送 prompt 到目标 LLM 并返回响应

        对于 sysprompt_extraction probe，使用 system role 设置测试系统提示词。

        Returns:
            (response_text, error_message)
        """
        headers = {"Content-Type": "application/json"}
        headers.update(auth_headers)

        messages = []
        probe_name = probe_data.get("probe_name", "")

        # sysprompt_extraction 需要设置 system role
        # many_shot 需要更大的 max_tokens（因为上下文很长）
        if probe_name == "many_shot":
            payload["max_tokens"] = 512  # 足够的输出空间
            payload["temperature"] = 0.1  # 略高的温度增加攻击成功率
        if probe_name == "sysprompt_extraction":
            test_prompts = probe_data.get("test_system_prompts", [])
            if test_prompts:
                system_prompt = random.choice(test_prompts)
                messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model_name or "gpt-4o",
            "messages": messages,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "temperature": 0.0,  # 确定性输出，便于检测
        }

        result = http_post(chat_url, json_data=payload, timeout=timeout, headers=headers)

        if result["status"] != 200:
            error = f"HTTP {result['status']}: {result.get('error', 'unknown')}"
            logger.debug("NativeProbe send failed: %s", error)
            return None, error

        # 解析响应
        data = result["data"]
        if isinstance(data, dict):
            # OpenAI 格式
            choices = data.get("choices", [])
            if choices:
                content = choices[0].get("message", {}).get("content", "")
                return content, None
            # Ollama 格式
            if "message" in data:
                content = data["message"].get("content", "")
                return content, None
            if "response" in data:
                return data["response"], None

        return str(data)[:500] if data else None, None

    # ── 响应检测 ──

    def _detect_responses(
        self,
        probe_name: str,
        probe_data: Dict[str, Any],
        detection_rules: List[Dict[str, Any]],
        prompt_response_pairs: List[Tuple[str, str]],
    ) -> List[Dict[str, Any]]:
        """检测所有响应并生成 findings"""
        findings: List[Dict[str, Any]] = []

        # 分类规则
        pattern_rules = [r for r in detection_rules if r.get("type") in ("regex", "keyword")]
        refusal_rules = [r for r in detection_rules if r.get("type") == "refusal_check"]

        pattern_detector = PatternDetector(pattern_rules) if pattern_rules else None
        refusal_detector = RefusalDetector(refusal_rules) if refusal_rules else None

        owasp = probe_data.get("owasp_mapping", PROBE_OWASP_MAP.get(probe_name, ""))
        severity = probe_data.get("severity", "medium")

        for prompt, response in prompt_response_pairs:
            # 模式检测
            if pattern_detector:
                p_result = pattern_detector.detect(prompt, response)
                if p_result.hit:
                    findings.append({
                        "category": probe_name,
                        "severity": severity,
                        "description": f"{probe_data.get('description', probe_name)}: {', '.join(p_result.matched_rules)}",
                        "evidence": p_result.evidence,
                        "owasp_mapping": owasp,
                        "confidence": p_result.confidence,
                        "trigger": prompt[:200],
                        "source": "native_probe",
                    })

            # 拒绝检测（仅当未通过模式检测时检查）
            if refusal_detector and not any(f["trigger"] == prompt[:200] for f in findings):
                r_result = refusal_detector.detect(prompt, response)
                if r_result.hit:
                    findings.append({
                        "category": f"{probe_name}_no_refusal",
                        "severity": severity,
                        "description": f"{probe_data.get('description', probe_name)}: {r_result.matched_rules[0]}",
                        "evidence": r_result.evidence,
                        "owasp_mapping": owasp,
                        "confidence": r_result.confidence,
                        "trigger": prompt[:200],
                        "source": "native_probe",
                    })

        return findings

    # ── 工具方法 ──

    @staticmethod
    def _resolve_chat_url(target: str) -> str:
        """
        将目标 URL 解析为聊天端点 URL

        支持：
        - http://host:port/v1/chat/completions → 直接使用
        - http://host:port/v1 → 追加 /chat/completions
        - http://host:port → 追加 /v1/chat/completions
        - http://host:port/api/chat → Ollama 格式，直接使用
        """
        url = target.rstrip("/")
        if url.endswith("/v1/chat/completions"):
            return url
        if url.endswith("/v1"):
            return f"{url}/chat/completions"
        if url.endswith("/api/chat"):
            return url
        if "/api/" in url:
            return url  # 假定用户已指定完整路径
        return f"{url}/v1/chat/completions"

    @staticmethod
    def _build_auth_headers(
        credential_headers: Dict[str, str],
        credential_bearer: str,
    ) -> Dict[str, str]:
        """构建认证头"""
        headers: Dict[str, str] = {}
        if credential_bearer:
            headers["Authorization"] = f"Bearer {credential_bearer}"
        elif credential_headers.get("Authorization", "").startswith("Bearer "):
            headers["Authorization"] = credential_headers["Authorization"]
        elif credential_headers.get("Cookie"):
            headers["Cookie"] = credential_headers["Cookie"]
        return headers

    @staticmethod
    def _apply_homoglyphs(text: str, glyph_map: Dict[str, str]) -> str:
        """应用同形字替换"""
        result = []
        for ch in text:
            replacement = glyph_map.get(ch)
            if replacement:
                result.append(replacement)
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _compute_cache_key(
        target: str, model_name: str, probes: List[str], depth: str
    ) -> str:
        """计算缓存键"""
        key_str = f"{target}|{model_name}|{','.join(sorted(probes))}|{depth}"
        return hashlib.md5(key_str.encode("utf-8")).hexdigest()

    @staticmethod
    def _load_cache(cache_key: str) -> Optional[Dict[str, Any]]:
        """加载缓存"""
        cache_file = Path(NATIVE_PROBE_CACHE_DIR) / f"{cache_key}.json"
        if not cache_file.exists():
            return None

        import time as _time
        mtime = cache_file.stat().st_mtime
        if _time.time() - mtime > 86400:  # 24h TTL
            return None

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    @staticmethod
    def _save_cache(cache_key: str, data: Dict[str, Any]) -> None:
        """保存缓存"""
        cache_dir = Path(NATIVE_PROBE_CACHE_DIR)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning("Failed to save native_probe cache: %s", e)
