"""
AI 侦测引擎主模块
================
编排所有侦察子模块，生成 target_profile.json。
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from recon.schema import (
    TargetProfile, ProfileMeta, TargetInfo, AuthInfo, RateLimitInfo,
    SpaInfo, ApiEndpoint, DynamicRoute, ReconArtifacts, RawProbeData,
    validate_profile, ApiFormat, EndpointType, AuthType, Confidence,
    JsSdkInfo, CredentialInfo, WafInfo, RagInfo,
    PromptExtractionInfo, BehaviorMapInfo, PhaseReport,
)
from recon.scanners.browser import BrowserManager
from recon.auth.login import LoginAutomator
from recon.scanners.traffic_capture import TrafficCapture
from recon.scanners.spa_router import SpaRouterAnalyzer
from recon.scanners.spa_interactor import SpaInteractor, InteractionResult
from recon.analysis.endpoint_infer import EndpointInferrer
from recon.scanners.dict_scan import DictScanner
from recon.probes.model_probe import probe_model_info, probe_to_summary
from recon.scanners.js_sdk_scanner import JsSdkScanner, JsSdkScanResult
from recon.scanners.credential_scanner import CredentialScanner, CredentialScanResult
from recon.scanners.waf_detector import WafDetector, WafScanResult
from recon.probes.rag_probe import RagProber, RagProbeResult
from recon.probes.prompt_extractor import PromptExtractor, PromptExtractionResult
from recon.analysis.behavior_mapper import BehaviorMapper, BehaviorMap
from recon.analysis.profile_builder import ProfileBuilder

console = Console()


class ReconEngine:
    """AI 侦测引擎 — 编排全部侦察流程。"""

    def __init__(
        self,
        target_url: str,
        login_url: str = "",
        login_cred: Optional[dict] = None,
        auth_cookie: str = "",
        auth_bearer: str = "",
        auth_headers: Optional[dict] = None,
        enable_spa_render: bool = True,
        enable_js_extraction: bool = True,
        enable_traffic_capture: bool = True,
        enable_dict_scan: bool = False,
        headless: bool = True,
        output_dir: str = "outputs",
        concurrency: int = 2,
        timeout: int = 30,
        verify_ssl: bool = False,
        ca_cert: Optional[str] = None,
        rate_profile: str = "stealth",
        interactive_login: bool = False,
        manual_login: bool = False,
        manual_login_timeout: int = 120,
    ):
        self.target_url = target_url.rstrip("/")
        self.login_url = login_url
        self.login_cred = login_cred or {}
        self.auth_cookie = auth_cookie
        self.auth_bearer = auth_bearer
        self.auth_headers = auth_headers or {}
        self.enable_spa_render = enable_spa_render
        self.enable_js_extraction = enable_js_extraction
        self.enable_traffic_capture = enable_traffic_capture
        self.enable_dict_scan = enable_dict_scan
        self.headless = headless
        self.output_dir = Path(output_dir)
        self.concurrency = concurrency
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.ca_cert = ca_cert
        self.verify = ca_cert if (verify_ssl and ca_cert) else verify_ssl
        self.rate_profile = rate_profile
        self.interactive_login = interactive_login
        self.manual_login = manual_login
        self.manual_login_timeout = manual_login_timeout

        self.profile = TargetProfile()
        self._setup_meta()
        self._setup_core()

        # 子模块（延迟初始化）
        self._browser: Optional[BrowserManager] = None
        self._login: Optional[LoginAutomator] = None
        self._traffic: Optional[TrafficCapture] = None
        self._spa: Optional[SpaRouterAnalyzer] = None
        self._interactor: Optional[SpaInteractor] = None
        self._inferrer: Optional[EndpointInferrer] = None
        self._dict_scanner: Optional[DictScanner] = None
        self._builder: Optional[ProfileBuilder] = None

        # 重要发现列表 — 扫描过程中由各 phase 实时追加，供 Web UI 轮询展示
        self.findings: list[dict] = []
        self._finding_seq = 0
        self._finding_lock = __import__("threading").Lock()

    def add_finding(self, phase: str, severity: str, title: str, detail: str = "",
                    data: Optional[dict] = None) -> dict:
        """追加一条重要发现。severity ∈ {critical, high, medium, low, info}。"""
        import time as _t
        with self._finding_lock:
            self._finding_seq += 1
            entry = {
                "id": self._finding_seq,
                "phase": phase,
                "severity": severity,
                "title": title,
                "detail": detail,
                "data": data or {},
                "ts": _t.time(),
            }
            self.findings.append(entry)
            return entry

    def _setup_meta(self):
        """初始化元信息。"""
        self.profile.meta.target_url = self.target_url
        self.profile.meta.generated_at = datetime.now(timezone.utc).isoformat()
        self.profile.target.base_url = self.target_url

    def _setup_core(self):
        """初始化核心目标参数。"""
        self.profile.target.verify_ssl = self.verify_ssl
        self.profile.target.request_timeout = self.timeout

        # 认证信息预填充
        if self.auth_cookie:
            self.profile.auth.type = AuthType.COOKIE.value
            self.profile.auth.session_cookie = self.auth_cookie
        elif self.auth_bearer:
            self.profile.auth.type = AuthType.BEARER.value
            self.profile.auth.bearer_token = self.auth_bearer
        if self.auth_headers:
            self.profile.auth.custom_headers.update(self.auth_headers)
            if self.profile.auth.type == AuthType.NONE.value:
                self.profile.auth.type = AuthType.CUSTOM_HEADER.value
        if self.login_url:
            self.profile.auth.login_url = self.login_url
        if self.login_cred:
            self.profile.auth.login_payload = self.login_cred

    # ── 主流程 ──

    async def run(self) -> TargetProfile:
        """执行完整侦察流程。"""
        t0 = time.monotonic()

        console.print()
        profile_labels = {"stealth": "🕵️ 隐身", "balanced": "⚖️ 平衡", "fast": "⚡ 快速"}
        rate_label = profile_labels.get(self.rate_profile, self.rate_profile)
        console.print(Panel(
            f"[bold cyan]🔍 AI 侦测引擎 v2.0[/bold cyan]\n"
            f"[dim]目标: {self.target_url}[/dim]\n"
            f"[dim]速率模式: {rate_label} | "
            f"SPA: {'✓' if self.enable_spa_render else '✗'} | "
            f"字典扫描: {'✓' if self.enable_dict_scan else '✗'}[/dim]\n"
            f"[dim]输出目录: {self.output_dir}[/dim]",
            style="bold blue",
        ))

        # Phase 0: 初始化模块
        await self._init_modules()

        # Phase 1: HTTP 基线探测（无浏览器，快速）
        await self._phase1_http_baseline()

        # Phase 2: 认证流程（如有登录需求）
        await self._phase2_auth()

        # Phase 3: SPA 渲染 + 流量捕获（浏览器）
        await self._phase3_spa_render()

        # Phase 3.5: JS SDK 指纹扫描（静态分析 JS bundles）
        await self._phase3_5_js_sdk_scan()

        # Phase 4: 端点枚举 + 字典扫描
        await self._phase4_endpoint_discovery()

        # Phase 4.5: 主动模型探测（POST 验证真实 AI 端点）
        await self._phase4_5_model_probe()

        # Phase 4.6: 响应密钥泄露扫描
        await self._phase4_6_credential_scan()

        # Phase 4.7: WAF/IPS 识别
        await self._phase4_7_waf_detect()

        # Phase 5: Chat 端点推断
        await self._phase5_endpoint_inference()

        # Phase 5.5: RAG/Agent 架构探测
        await self._phase5_5_rag_probe()

        # Phase 3 (用户视角): 提示词提取 — 注入探针提取系统规则/工具/密钥前缀
        await self._phase3_prompt_extraction()

        # Phase 5 (用户视角): 行为测绘 — 综合评分 + 攻击路线图
        await self._phase5_behavior_mapping()

        # Phase 6: 组装 Profile + 生成分阶段报告
        await self._phase6_build_profile()

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        self.profile.meta.probe_duration_ms = elapsed_ms

        # 验证
        is_valid, errors = validate_profile(self.profile)
        if not is_valid:
            console.print("[yellow]⚠ Profile 验证警告:[/yellow]")
            for err in errors:
                console.print(f"  [dim]  • {err}[/dim]")
                self.profile.artifacts.warnings.append(err)

        # 保存
        output_path = self._save_profile()
        console.print()
        console.print(Panel(
            f"[bold green]✅ 侦察完成![/bold green]\n"
            f"[dim]耗时: {elapsed_ms}ms | 端点: {len(self.profile.api_endpoints)} | "
            f"动态路由: {len(self.profile.dynamic_routes)}[/dim]\n"
            f"[bold]输出: [cyan]{output_path}[/cyan][/bold]",
            style="bold green",
        ))

        return self.profile

    async def _init_modules(self):
        """初始化所有子模块。"""
        console.print("[dim]⚙ 初始化侦测模块...[/dim]")

        if self.enable_spa_render:
            self._browser = BrowserManager(
                headless=self.headless,
                output_dir=str(self.output_dir),
            )
            await self._browser.start()
            self._login = LoginAutomator(self._browser)
            self._traffic = TrafficCapture(self._browser)
            self._spa = SpaRouterAnalyzer(self._browser)
            self._interactor = SpaInteractor(self._browser)

        self._inferrer = EndpointInferrer()
        self._dict_scanner = DictScanner(
            concurrency=self.concurrency,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
            ca_cert=self.ca_cert,
            rate_profile=self.rate_profile,
        )
        self._js_sdk_scanner = JsSdkScanner()
        self._credential_scanner = CredentialScanner()
        self._waf_detector = WafDetector()
        self._rag_prober = RagProber(
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
            ca_cert=self.ca_cert,
        )
        self._prompt_extractor = PromptExtractor(
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
            ca_cert=self.ca_cert,
        )
        self._behavior_mapper = BehaviorMapper()
        self._builder = ProfileBuilder(self.profile)
        self._phase_reports: list[PhaseReport] = []

    # ── Phase 实现 ──

    async def _phase1_http_baseline(self):
        """Phase 1: HTTP 基线探测（httpx，无浏览器）。"""
        console.print()
        console.print("[bold cyan]📡 Phase 1: HTTP 基线探测[/bold cyan]")

        # 快速 HTTP GET 根路径
        import httpx
        try:
            client_kwargs = {
                "verify": self.verify,
                "timeout": httpx.Timeout(self.timeout),
                "follow_redirects": True,
            }
            if self.auth_headers:
                client_kwargs["headers"] = self.auth_headers

            async with httpx.AsyncClient(**client_kwargs) as client:
                resp = await client.get(self.target_url)
                self.profile.raw_probe_data.http_headers = dict(resp.headers)
                self.profile.raw_probe_data.server_header = resp.headers.get("server", "")
                self.profile.raw_probe_data.powered_by = resp.headers.get("x-powered-by", "")

                if "text/html" in resp.headers.get("content-type", ""):
                    # 提取标题
                    import re
                    title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                    if title_match:
                        self.profile.raw_probe_data.homepage_title = title_match.group(1)
                    self.profile.raw_probe_data.homepage_text_snippet = resp.text[:500]

                console.print(
                    f"  [dim]HTTP {resp.status_code} | "
                    f"Server: {self.profile.raw_probe_data.server_header or 'N/A'} | "
                    f"Content-Type: {resp.headers.get('content-type', 'N/A')[:50]}[/dim]"
                )
                self.add_finding(
                    "Phase 1 · HTTP 基线",
                    "info",
                    f"HTTP {resp.status_code} — {self.profile.raw_probe_data.server_header or 'unknown server'}",
                    f"Content-Type: {resp.headers.get('content-type', 'N/A')[:60]}; "
                    f"页面标题: {self.profile.raw_probe_data.homepage_title or '(无)'}",
                    {
                        "status": resp.status_code,
                        "server": self.profile.raw_probe_data.server_header,
                        "title": self.profile.raw_probe_data.homepage_title,
                    },
                )

                # robots.txt
                try:
                    robots_resp = await client.get(f"{self.target_url}/robots.txt")
                    if robots_resp.status_code == 200:
                        self.profile.raw_probe_data.robots_txt = robots_resp.text[:2000]
                        console.print(f"  [dim]robots.txt: {len(self.profile.raw_probe_data.robots_txt)} 字符[/dim]")
                        self.add_finding(
                            "Phase 1 · HTTP 基线",
                            "low",
                            f"robots.txt 已发现 ({len(self.profile.raw_probe_data.robots_txt)} 字符)",
                            "可能暴露隐藏路径",
                            {"url": f"{self.target_url}/robots.txt"},
                        )
                except Exception:
                    pass

        except Exception as e:
            self.profile.artifacts.errors.append(f"Phase1 HTTP baseline: {e}")
            console.print(f"  [yellow]⚠ HTTP 基线探测失败: {e}[/yellow]")

    async def _phase2_auth(self):
        """Phase 2: 认证流程自动化。

        支持四种模式（按优先级）:
        1. 参数自动登录 (--login-cred): JSON 凭据
        2. CLI 安全输入 (--interactive-login): 终端提示输入密码
        3. 手动登录捕获 (--manual-login): headed 浏览器手动登录
        4. Cookie/Bearer 注入: 直接跳过登录
        """
        # 如果没有浏览器，只处理 Bearer/Cookie 注入
        if not self._browser or not self._login:
            return

        # 决定使用哪种登录模式
        login_mode = None  # "auto" / "interactive" / "manual"
        if self.manual_login:
            login_mode = "manual"
        elif self.interactive_login:
            login_mode = "interactive"
        elif self.login_cred:
            login_mode = "auto"
        else:
            return  # 无登录需求

        console.print()
        console.print("[bold cyan]🔐 Phase 2: 认证流程[/bold cyan]")

        login_url = self.login_url or self.target_url

        try:
            if login_mode == "manual":
                result = await self._login.manual_login(
                    login_url=login_url,
                    wait_timeout=self.manual_login_timeout,
                )
            elif login_mode == "interactive":
                result = await self._login.interactive_login(
                    login_url=login_url,
                    timeout=self.timeout,
                )
            else:
                result = await self._login.auto_login(
                    login_url=login_url,
                    credentials=self.login_cred,
                )

            if result.success:
                self.profile.auth = result.to_auth_info()
                # 回填到 traffic capture
                if self._traffic and result.cookies:
                    self._traffic.set_cookies(result.cookies)
                console.print(
                    f"  [green]✅ 登录成功[/green] "
                    f"[dim](cookies: {len(result.cookies)}, "
                    f"耗时: {result.duration_ms}ms)[/dim]"
                )
                self.profile.artifacts.login_flow_trace = result.trace_log
            else:
                console.print(f"  [yellow]⚠ 登录失败: {result.error}[/yellow]")
                self.profile.artifacts.warnings.append(f"Login failed: {result.error}")
        except Exception as e:
            console.print(f"  [yellow]⚠ 认证流程异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase2 auth: {e}")

    async def _phase3_spa_render(self):
        """Phase 3: SPA 渲染 + 流量捕获。"""
        if not self._browser:
            return

        console.print()
        console.print("[bold cyan]🌐 Phase 3: SPA 渲染 + 流量捕获[/bold cyan]")

        try:
            # 打开目标 URL
            page = await self._browser.new_page()

            # 启动流量捕获
            if self.enable_traffic_capture and self._traffic:
                self._traffic.start_capture(page)

            # 导航到目标
            console.print(f"  [dim]→ 导航到: {self.target_url}[/dim]")
            await page.goto(self.target_url, wait_until="networkidle", timeout=self.timeout * 1000)

            # 等待 SPA 渲染完成
            await asyncio.sleep(2)

            # 截图
            screenshot_path = str(self.output_dir / "screenshot_landing.png")
            await page.screenshot(path=screenshot_path, full_page=True)
            self.profile.artifacts.screenshots.append(screenshot_path)
            console.print(f"  [dim]📸 截图已保存: {screenshot_path}[/dim]")

            # SPA 分析
            if self._spa:
                spa_info = await self._spa.analyze(page)
                self.profile.spa_info = spa_info
                if spa_info.is_spa:
                    console.print(
                        f"  [green]✅ SPA 检测: [cyan]{spa_info.framework}[/cyan] "
                        f"(路由模式: {spa_info.router_mode})[/green]"
                    )
                    console.print(
                        f"  [dim]  JS Bundles: {len(spa_info.js_bundle_urls)} | "
                        f"API Base: {spa_info.api_base_url or 'N/A'}[/dim]"
                    )
                    self.add_finding(
                        "Phase 3 · SPA 渲染",
                        "info",
                        f"SPA 框架: {spa_info.framework}",
                        f"路由模式: {spa_info.router_mode}; "
                        f"JS Bundles: {len(spa_info.js_bundle_urls)}; "
                        f"API Base: {spa_info.api_base_url or 'N/A'}",
                        {
                            "framework": spa_info.framework,
                            "router_mode": spa_info.router_mode,
                            "js_bundles": len(spa_info.js_bundle_urls),
                            "api_base": spa_info.api_base_url,
                        },
                    )
                else:
                    console.print("  [dim]非 SPA 应用 (传统多页面)[/dim]")

            # 提取流量中的 API 端点
            if self._traffic:
                endpoints = await self._traffic.stop_capture()
                console.print(f"  [dim]📡 捕获到 {len(endpoints)} 个网络请求[/dim]")
                # 将捕获的端点加入 profile
                for ep in endpoints:
                    api_ep = self._inferrer.classify_endpoint(ep)
                    self.profile.api_endpoints.append(api_ep)

                # 重要发现: 流量捕获
                if endpoints:
                    chat_eps = [e for e in self.profile.api_endpoints if e.is_chat_endpoint]
                    if chat_eps:
                        for cep in chat_eps[:3]:
                            self.add_finding(
                                "Phase 3 · 流量捕获",
                                "high",
                                f"🎯 Chat 端点捕获: {cep.path or cep.full_url}",
                                f"方法: {cep.method}; 可能为 AI 对话 API",
                                {"path": cep.path, "method": cep.method, "full_url": cep.full_url},
                            )
                    self.add_finding(
                        "Phase 3 · 流量捕获",
                        "info",
                        f"浏览器流量: 捕获 {len(endpoints)} 个网络请求",
                        f"其中 Chat 端点 {len(chat_eps)} 个",
                        {"total_endpoints": len(endpoints), "chat_endpoints": len(chat_eps)},
                    )

            await self._browser.close_page(page)

        except Exception as e:
            console.print(f"  [yellow]⚠ SPA 渲染异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase3 spa_render: {e}")

    async def _phase3_5_js_sdk_scan(self):
        """Phase 3.5: JS SDK 指纹扫描 — 从 JS bundles 识别 AI SDK 引用。

        扫描所有收集到的 JavaScript 文件中的 AI SDK 签名：
        - OpenAI/Anthropic/Google/Mistral/Cohere/Groq/Replicate 等提供商
        - LangChain/LlamaIndex/Vercel AI SDK 等框架
        - Ollama/vLLM/LiteLLM/OpenRouter 等平台
        - 提取 gateway/base URL
        """
        console.print()
        console.print("[bold cyan]📦 Phase 3.5: JS SDK 指纹扫描[/bold cyan]")

        try:
            # 收集所有 JS 内容
            scripts = {}

            # 来自 SPA 的 JS bundle URLs
            if self.profile.spa_info.js_bundle_urls:
                for url in self.profile.spa_info.js_bundle_urls:
                    js_url = url if isinstance(url, str) else url.get("url", "")
                    if js_url:
                        scripts[js_url] = ""  # 稍后从浏览器获取

            # 如果有浏览器实例，尝试获取 JS 内容
            if self._browser and self.enable_js_extraction:
                try:
                    page = await self._browser.new_page()
                    # 从页面上下文提取内联 JS 和外部 bundle 内容
                    js_contents = await self._browser.extract_js_contents(page)
                    if js_contents:
                        for fname, content in js_contents.items():
                            if content and len(content) > 100:
                                scripts[fname] = content
                    await self._browser.close_page(page)
                except Exception as e:
                    console.print(f"  [dim]  浏览器 JS 提取跳过: {e}[/dim]")

            # 也扫描 HAR 捕获的响应体中的 JS
            if self.profile.raw_probe_data.http_headers:
                # 从所有 API 端点中筛选 JS 响应
                for ep in self.profile.api_endpoints:
                    if "javascript" in ep.content_type or ep.path.endswith(".js"):
                        snippet = ep.body_snippet
                        if snippet and len(snippet) > 100:
                            scripts[ep.path] = snippet

            if not scripts:
                console.print("  [dim]⏭ 无 JS 文件可扫描[/dim]")
                return

            # 执行扫描
            result = self._js_sdk_scanner.scan_multiple(scripts)

            if result.findings:
                console.print(
                    f"  [green]✅ JS SDK 指纹: "
                    f"{len(result.findings)} 个 AI SDK/框架[/green]"
                )
                for f in result.findings[:8]:
                    console.print(
                        f"    [dim]• {f.provider} ({f.type}), "
                        f"置信度: {f.confidence}[/dim]"
                    )
                # JS SDK 发现记录
                for f in result.findings[:5]:
                    sev = "high" if f.confidence == "high" else "medium" if f.confidence == "medium" else "low"
                    self.add_finding(
                        "Phase 3.5 · JS SDK",
                        sev,
                        f"🔌 {f.provider} ({f.type})",
                        f"置信度: {f.confidence}; 来源: {f.source_file or 'N/A'}",
                        {"provider": f.provider, "type": f.type, "confidence": f.confidence},
                    )
                if result.extracted_api_urls:
                    console.print(
                        f"  [yellow]  ⚡ 提取到 API URL: "
                        f"{len(result.extracted_api_urls)} 个[/yellow]"
                    )
                    for url in result.extracted_api_urls[:3]:
                        console.print(f"    [dim]    {url}[/dim]")
                    self.add_finding(
                        "Phase 3.5 · JS SDK",
                        "high",
                        f"⚡ 从 JS 中提取到 {len(result.extracted_api_urls)} 个 API URL",
                        "可能包含隐藏的 AI API 网关地址",
                        {"urls": result.extracted_api_urls[:5]},
                    )
            else:
                console.print("  [dim]  未发现 AI SDK 引用[/dim]")

            # 应用结果到 profile
            self.profile.js_sdk = JsSdkInfo(
                findings=[{
                    "provider": f.provider,
                    "type": f.type,
                    "confidence": f.confidence,
                    "extracted_urls": f.extracted_urls,
                    "match_snippet": f.match_snippet,
                    "source_file": f.source_file,
                } for f in result.findings],
                total_scripts_scanned=result.total_scripts_scanned,
                total_matches=result.total_matches,
                extracted_api_urls=result.extracted_api_urls,
                summary=result.summary,
            )

            # 将提取的 API URL 加入端点发现
            for url in result.extracted_api_urls[:10]:
                if url not in [ep.full_url for ep in self.profile.api_endpoints]:
                    self.profile.api_endpoints.append(ApiEndpoint(
                        path=url,
                        full_url=url,
                        method="POST",
                        category="chat",
                        confidence=Confidence.MEDIUM.value,
                    ))

        except Exception as e:
            console.print(f"  [yellow]⚠ JS SDK 扫描异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase3.5 js_sdk_scan: {e}")

    async def _phase4_endpoint_discovery(self):
        """Phase 4: 端点枚举 + 字典扫描。"""
        console.print()
        console.print("[bold cyan]📋 Phase 4: 端点枚举[/bold cyan]")

        if not self.enable_dict_scan:
            console.print("  [dim]⏭ 字典扫描已禁用[/dim]")
            return

        try:
            scan_results = await self._dict_scanner.scan(
                base_url=self.target_url,
                extra_headers=self.auth_headers,
            )
            for result in scan_results:
                if result.get("status", 0) in (200, 401, 403):
                    ep = ApiEndpoint(
                        path=result.get("path", ""),
                        full_url=f"{self.target_url}{result.get('path', '')}",
                        method="GET",
                        status=result.get("status", 0),
                        content_type=result.get("content_type", ""),
                        response_time_ms=result.get("response_time_ms", 0.0),
                        body_snippet=result.get("body_snippet", "")[:300],
                    )
                    # 分类
                    ep = self._inferrer.classify_endpoint({
                        "url": ep.full_url,
                        "status": ep.status,
                        "content_type": ep.content_type,
                        "body": result.get("body_snippet", ""),
                    })
                    self.profile.api_endpoints.append(ep)

            console.print(f"  [dim]字典扫描完成: 新增 {len(scan_results)} 个端点结果[/dim]")

        except Exception as e:
            console.print(f"  [yellow]⚠ 端点枚举异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase4 endpoint_discovery: {e}")

    async def _phase4_5_model_probe(self):
        """Phase 4.5: 主动模型探测 — POST 发送真实请求验证 AI 端点。

        不同于 Phase 4 的纯 GET 字典扫描和 Phase 5 的正则匹配，
        这个阶段真正发送 AI 模型请求来验证：
        - 目标是否真的是 AI 服务
        - 模型名称是什么
        - 用的是哪种框架（Ollama/vLLM/OpenAI/...）
        - 速率限制配置
        """
        console.print()
        console.print("[bold cyan]🔬 Phase 4.5: 主动模型探测[/bold cyan]")

        try:
            result = await probe_model_info(
                target_url=self.target_url,
                timeout=self.timeout,
                verify_ssl=self.verify_ssl,
                ca_cert=self.ca_cert,
                extra_auth_headers=self.auth_headers if self.auth_headers else None,
                rate_profile=self.rate_profile,
            )

            if result.model_name:
                console.print(
                    f"  [green]✅ 模型识别: [bold cyan]{result.model_name}[/bold cyan]"
                    f" (策略: {result.strategy}, 置信度: {result.confidence:.0%})[/green]"
                )
                self.add_finding(
                    "Phase 4.5 · 模型探测",
                    "high",
                    f"🤖 识别模型: {result.model_name}",
                    f"探测策略: {result.strategy}; 置信度: {result.confidence:.0%}",
                    {"model": result.model_name, "strategy": result.strategy, "confidence": result.confidence},
                )
            else:
                console.print(
                    f"  [yellow]⚠ 未识别到模型名称 (策略: {result.strategy or 'N/A'}, "
                    f"置信度: {result.confidence:.0%})[/yellow]"
                )

            if result.framework and result.framework != "unknown":
                console.print(
                    f"  [dim]  框架指纹: {result.framework} "
                    f"(置信度: {result.framework_confidence})[/dim]"
                )
                self.add_finding(
                    "Phase 4.5 · 模型探测",
                    "medium",
                    f"🛠 框架指纹: {result.framework}",
                    f"框架置信度: {result.framework_confidence}",
                    {"framework": result.framework, "confidence": result.framework_confidence},
                )

            # 端点发现摘要
            live_eps = sum(1 for e in result.discovered_endpoints if e.status == 200)
            console.print(
                f"  [dim]  端点枚举: {len(result.discovered_endpoints)} 个路径探测, "
                f"{live_eps} 个存活[/dim]"
            )
            if live_eps > 0:
                # 列出存活的端点
                for ep in [e for e in result.discovered_endpoints if e.status == 200][:5]:
                    self.add_finding(
                        "Phase 4.5 · 模型探测",
                        "high",
                        f"🎯 存活端点: {ep.path} → HTTP {ep.status}",
                        f"Content-Type: {(ep.content_type or 'N/A')[:60]}",
                        {"path": ep.path, "status": ep.status, "content_type": ep.content_type},
                    )

            # 速率限制
            if result.total_429s > 0:
                console.print(
                    f"  [yellow]  ⚡ 检测到速率限制: {result.total_429s} 次 429[/yellow]"
                )
                self.add_finding(
                    "Phase 4.5 · 模型探测",
                    "medium",
                    f"⚡ 检测到速率限制: {result.total_429s} 次 429",
                    "目标存在 rate-limit 防护",
                    {"total_429s": result.total_429s},
                )
            if result.rate_limit_info and result.rate_limit_info.limit_requests:
                console.print(
                    f"  [dim]  推荐并发: {result.recommended_concurrency}, "
                    f"推荐 RPM: {result.recommended_rpm}[/dim]"
                )
                self.add_finding(
                    "Phase 4.5 · 模型探测",
                    "low",
                    f"📊 速率限制: RPM {result.rate_limit_info.limit_requests}",
                    f"推荐并发: {result.recommended_concurrency}; 推荐 RPM: {result.recommended_rpm}",
                    {"rpm": result.rate_limit_info.limit_requests},
                )

            # 应用到 profile
            summary = probe_to_summary(result)
            self._builder.apply_model_probe(summary)

            if result.errors:
                self.profile.artifacts.warnings.extend(result.errors)

        except Exception as e:
            console.print(f"  [yellow]⚠ 主动模型探测异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase4.5 model_probe: {e}")

    async def _phase4_6_credential_scan(self):
        """Phase 4.6: 响应密钥泄露扫描。

        扫描所有 HTTP 响应体和 JS 源码中的 API 密钥泄露：
        - OpenAI/Anthropic/Google/Mistral 等 25+ 种密钥模式
        - AWS/Azure/GCP 云服务密钥
        - Bearer Token 等通用凭证
        """
        console.print()
        console.print("[bold cyan]🔑 Phase 4.6: 密钥泄露扫描[/bold cyan]")

        try:
            # 收集所有待扫描文本
            texts = []

            # 根路径响应
            if self.profile.raw_probe_data.homepage_text_snippet:
                texts.append((
                    self.profile.raw_probe_data.homepage_text_snippet,
                    "response_body",
                    f"{self.target_url}/ (homepage)",
                ))

            # HTTP 响应头
            if self.profile.raw_probe_data.http_headers:
                texts.append((
                    "\n".join(f"{k}: {v}" for k, v in self.profile.raw_probe_data.http_headers.items()),
                    "http_header",
                    f"{self.target_url}/ (response headers)",
                ))

            # 已发现的端点响应体
            for ep in self.profile.api_endpoints:
                if ep.body_snippet and len(ep.body_snippet) > 50:
                    texts.append((
                        ep.body_snippet,
                        "response_body",
                        ep.full_url or ep.path,
                    ))

            # JS 源码（从 JS SDK 扫描中已收集的）
            if hasattr(self, '_cached_js_scripts'):
                for fname, content in self._cached_js_scripts.items():
                    if content and len(content) > 100:
                        texts.append((content, "js_file", fname))

            if not texts:
                console.print("  [dim]⏭ 无可扫描文本（无响应体或 JS 文件）[/dim]")
                return

            # 执行扫描
            result = self._credential_scanner.scan_batch(texts)

            if result.findings:
                if result.critical_count > 0:
                    console.print(
                        f"  [red]🚨 严重: {result.critical_count} 个严重密钥泄露![/red]"
                    )
                    self.add_finding(
                        "Phase 4.6 · 密钥扫描",
                        "critical",
                        f"🚨 严重: {result.critical_count} 个严重密钥泄露",
                        "HTTP 响应中检测到高危 API Key, 建议立即停用",
                        {"critical_count": result.critical_count},
                    )
                if result.high_count > 0:
                    console.print(
                        f"  [yellow]⚠ 高危: {result.high_count} 个高危密钥泄露[/yellow]"
                    )
                    self.add_finding(
                        "Phase 4.6 · 密钥扫描",
                        "high",
                        f"⚠ 高危: {result.high_count} 个高危密钥泄露",
                        "高危凭证可能为内部云服务密钥",
                        {"high_count": result.high_count},
                    )
                for f in result.findings[:6]:
                    risk_color = "red" if f.risk_level == "critical" else "yellow" if f.risk_level == "high" else "dim"
                    console.print(
                        f"  [{risk_color}]  {f.platform}/{f.credential_type} "
                        f"({f.source})[/{risk_color}]"
                    )
                    if f.risk_level in ("critical", "high"):
                        self.add_finding(
                            "Phase 4.6 · 密钥扫描",
                            "critical" if f.risk_level == "critical" else "high",
                            f"{f.platform} 凭证泄露",
                            f"类型: {f.credential_type}; 来源: {f.source}; 风险: {f.risk_level}",
                            {"platform": f.platform, "type": f.credential_type, "source": f.source},
                        )
            else:
                console.print("  [green]✅ 未发现密钥泄露[/green]")

            self.profile.credentials = CredentialInfo(
                findings=[{
                    "credential_type": f.credential_type,
                    "platform": f.platform,
                    "risk_level": f.risk_level,
                    "match_snippet": f.match_snippet,
                    "source": f.source,
                    "source_detail": f.source_detail,
                } for f in result.findings],
                total_scanned=result.total_scanned,
                critical_count=result.critical_count,
                high_count=result.high_count,
                summary=result.summary,
            )

        except Exception as e:
            console.print(f"  [yellow]⚠ 密钥扫描异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase4.6 credential_scan: {e}")

    async def _phase4_7_waf_detect(self):
        """Phase 4.7: WAF/CDN/IPS 识别。

        检测目标前端的 20+ 种安全防护设施：
        - Cloudflare / AWS WAF / Google Cloud Armor / Azure WAF
        - Imperva / F5 / Akamai / Fortinet / Barracuda
        - ModSecurity / NAXSI / Kong API Gateway
        """
        console.print()
        console.print("[bold cyan]🛡 Phase 4.7: WAF/IPS 识别[/bold cyan]")

        try:
            headers = self.profile.raw_probe_data.http_headers or {}
            body = self.profile.raw_probe_data.homepage_text_snippet or ""

            # 也扫描端点响应头以获得更全面的检测
            all_headers = dict(headers)
            for ep in self.profile.api_endpoints[:10]:
                # 端点没有单独的 header 信息，用根响应头作为代理
                pass

            result = self._waf_detector.detect(
                headers=all_headers,
                body=body,
            )

            if result.detections:
                high_confs = [d for d in result.detections if d.confidence == "high"]
                if high_confs:
                    console.print(
                        f"  [yellow]🛡 检测到 WAF: "
                        f"{', '.join(d.name for d in high_confs)}[/yellow]"
                    )
                    self.add_finding(
                        "Phase 4.7 · WAF 探测",
                        "high",
                        f"🛡 检测到 WAF: {', '.join(d.name for d in high_confs)}",
                        f"厂商: {', '.join(set(d.vendor for d in high_confs))}",
                        {"detections": [d.name for d in high_confs]},
                    )
                for d in result.detections:
                    conf_icon = "🔴" if d.confidence == "high" else "🟡" if d.confidence == "medium" else "⚪"
                    console.print(
                        f"    {conf_icon} {d.name} ({d.vendor}) "
                        f"[dim]- {d.match_type}: {d.evidence[:80]}[/dim]"
                    )
                if result.implications:
                    console.print(f"  [dim]  💡 {result.implications[:200]}...[/dim]")
            else:
                console.print("  [green]✅ 未检测到 WAF[/green]")

            self.profile.waf = WafInfo(
                detections=[{
                    "name": d.name,
                    "vendor": d.vendor,
                    "confidence": d.confidence,
                    "evidence": d.evidence,
                    "match_type": d.match_type,
                } for d in result.detections],
                waf_count=result.waf_count,
                summary=result.summary,
                implications=result.implications,
            )

            # 将 WAF 信息写入 raw_probe_data
            if result.waf_count > 0:
                waf_names = ", ".join(d.name for d in result.detections)
                self.profile.raw_probe_data.waf_detected = waf_names

        except Exception as e:
            console.print(f"  [yellow]⚠ WAF 检测异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase4.7 waf_detect: {e}")

    async def _phase5_endpoint_inference(self):
        """Phase 5: Chat 端点推断 + 动态路由发现。"""
        console.print()
        console.print("[bold cyan]🧠 Phase 5: 端点推断[/bold cyan]")

        try:
            # 从已有端点推断 Chat API
            inferences = self._inferrer.infer_chat_endpoint(
                self.profile.api_endpoints,
                base_url=self.target_url,
            )
            if inferences.chat_api_url:
                self.profile.target.chat_api_url = inferences.chat_api_url
                console.print(
                    f"  [green]✅ Chat API 推断: [cyan]{inferences.chat_api_url}[/cyan][/green]"
                )
                self.add_finding(
                    "Phase 5 · 端点推断",
                    "high",
                    f"🧠 Chat API 推断: {inferences.chat_api_url}",
                    f"API 格式: {inferences.api_format or 'N/A'}; 端点类型: {inferences.endpoint_type or 'N/A'}",
                    {"url": inferences.chat_api_url, "format": inferences.api_format, "type": inferences.endpoint_type},
                )
            if inferences.api_format:
                self.profile.target.api_format = inferences.api_format
                console.print(f"  [dim]  API 格式: {inferences.api_format}[/dim]")
            if inferences.endpoint_type:
                self.profile.target.endpoint_type = inferences.endpoint_type
                console.print(f"  [dim]  端点类型: {inferences.endpoint_type}[/dim]")

            # 动态路由推断
            dynamic = self._inferrer.infer_dynamic_routes(
                self.profile.api_endpoints,
                base_url=self.target_url,
            )
            self.profile.dynamic_routes = dynamic
            if dynamic:
                console.print(f"  [dim]🔗 推断出 {len(dynamic)} 条动态路由[/dim]")
                for dr in dynamic[:5]:
                    console.print(f"    [dim]• {dr.pattern} (from: {dr.inferred_from})[/dim]")
                self.add_finding(
                    "Phase 5 · 端点推断",
                    "medium",
                    f"🔗 推断出 {len(dynamic)} 条动态路由",
                    f"示例: {', '.join(dr.pattern for dr in dynamic[:3])}",
                    {"routes": [dr.pattern for dr in dynamic[:10]]},
                )

        except Exception as e:
            console.print(f"  [yellow]⚠ 端点推断异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase5 endpoint_inference: {e}")

    async def _phase5_5_rag_probe(self):
        """Phase 5.5: RAG/Agent 架构探测。

        通过发送探针 prompt 检测目标架构：
        - RAG pipeline 存在性 + 数据源枚举
        - Agent 工具/权限/委托链
        - 多智能体系统
        - Guardrail 策略
        - Agent Card (.well-known/agent.json) 发现
        """
        console.print()
        console.print("[bold cyan]🏗 Phase 5.5: RAG/Agent 架构探测[/bold cyan]")

        # 需要找到 chat endpoint
        chat_url = self.profile.target.chat_api_url
        if not chat_url:
            # 尝试从已发现的端点中找
            for ep in self.profile.api_endpoints:
                if ep.is_chat_endpoint:
                    chat_url = ep.full_url
                    break

        if not chat_url:
            console.print("  [dim]⏭ 未找到 Chat 端点，跳过架构探测[/dim]")
            return

        try:
            # 执行 RAG/Agent 探测
            result = await self._rag_prober.probe(
                chat_url=chat_url,
                model_name=self.profile.target.model_name,
                extra_headers=self.auth_headers if self.auth_headers else None,
            )

            # 架构类型显示
            arch_display = {
                "basic_llm": "🎯 纯 LLM",
                "rag": "📚 RAG 系统",
                "agent": "🤖 Agent 系统",
                "multi_agent": "👥 多智能体系统",
            }
            console.print(
                f"  [green]架构: {arch_display.get(result.target_architecture, result.target_architecture)}[/green]"
            )
            self.add_finding(
                "Phase 5.5 · 架构探测",
                "high",
                f"🏗 架构: {arch_display.get(result.target_architecture, result.target_architecture)}",
                f"target_architecture: {result.target_architecture}",
                {"architecture": result.target_architecture},
            )

            if result.is_rag:
                console.print(
                    f"  [dim]  RAG 置信度: {result.rag_confidence:.0%}, "
                    f"数据源: {len(result.rag_data_sources)} 个[/dim]"
                )
                self.add_finding(
                    "Phase 5.5 · 架构探测",
                    "medium",
                    f"📚 RAG 系统: 置信度 {result.rag_confidence:.0%}",
                    f"数据源: {len(result.rag_data_sources)} 个",
                    {"rag_confidence": result.rag_confidence, "data_sources_count": len(result.rag_data_sources)},
                )
            if result.is_agent:
                console.print(
                    f"  [dim]  Agent: {result.agent_tools_count} 个工具, "
                    f"Memory: {'✓' if result.has_memory else '✗'}, "
                    f"Browsing: {'✓' if result.has_browsing else '✗'}[/dim]"
                )
                self.add_finding(
                    "Phase 5.5 · 架构探测",
                    "high",
                    f"🤖 Agent 系统: {result.agent_tools_count} 个工具",
                    f"Memory: {result.has_memory}; Browsing: {result.has_browsing}",
                    {"agent_tools": result.agent_tools_count, "memory": result.has_memory, "browsing": result.has_browsing},
                )
            if result.is_multi_agent:
                console.print("  [yellow]  ⚡ 检测到多智能体委托链[/yellow]")
                self.add_finding(
                    "Phase 5.5 · 架构探测",
                    "critical",
                    "⚡ 检测到多智能体委托链",
                    "Agent 之间存在权限委托, 可能形成横向越权攻击面",
                    {},
                )
            if result.guardrail_detected:
                console.print(
                    f"  [dim]  🛡 Guardrail: 已检测 "
                    f"({len(result.guardrail_boundaries)} 个检测点)[/dim]"
                )
                self.add_finding(
                    "Phase 5.5 · 架构探测",
                    "low",
                    f"🛡 Guardrail: {len(result.guardrail_boundaries)} 个检测点",
                    "目标存在安全护栏机制",
                    {"boundaries": len(result.guardrail_boundaries)},
                )

            # Agent Card 发现
            agent_card = await self._rag_prober.discover_agent_card(
                self.target_url,
                extra_headers=self.auth_headers if self.auth_headers else None,
            )
            if agent_card.get("found"):
                result.agent_card_discovered = True
                result.agent_card_url = agent_card["url"]
                console.print(
                    f"  [green]  📋 Agent Card 发现: {agent_card['url']}[/green]"
                )
                self.add_finding(
                    "Phase 5.5 · 架构探测",
                    "medium",
                    f"📋 Agent Card: {agent_card['url']}",
                    "目标暴露了 A2A/Agent 协议元数据",
                    {"url": agent_card["url"]},
                )

            # 应用结果
            self.profile.rag_probe = RagInfo(
                is_rag=result.is_rag,
                is_agent=result.is_agent,
                is_multi_agent=result.is_multi_agent,
                has_tools=result.has_tools,
                has_memory=result.has_memory,
                has_browsing=result.has_browsing,
                target_architecture=result.target_architecture,
                rag_confidence=result.rag_confidence,
                rag_data_sources=result.rag_data_sources,
                agent_tools=result.agent_tools,
                agent_tools_count=result.agent_tools_count,
                agent_delegation_detected=result.agent_delegation_detected,
                agent_card_discovered=result.agent_card_discovered,
                agent_card_url=result.agent_card_url,
                guardrail_detected=result.guardrail_detected,
                guardrail_boundaries=result.guardrail_boundaries,
                summary=result.summary,
            )

            # 更新 target_type
            arch_to_target_type = {
                "basic_llm": "basic_llm",
                "rag": "rag",
                "agent": "agent",
                "multi_agent": "multi_agent",
            }
            if result.target_architecture in arch_to_target_type:
                self.profile.target.target_type = arch_to_target_type[result.target_architecture]

        except Exception as e:
            console.print(f"  [yellow]⚠ 架构探测异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase5.5 rag_probe: {e}")

    async def _phase3_prompt_extraction(self):
        """Phase 3 (用户视角): 提示词提取探测。

        通过注入/越狱探针从目标 AI 提取：
        - 系统提示词片段
        - 内部工具/函数清单
        - 安全边界规则 (Guardrail)
        - 密钥前缀
        - 模型能力 + 知识截止日期
        - 风险评分
        """
        console.print()
        console.print("[bold cyan]💉 Phase 3: 提示词提取探测[/bold cyan]")

        chat_url = self.profile.target.chat_api_url
        if not chat_url:
            for ep in self.profile.api_endpoints:
                if ep.is_chat_endpoint:
                    chat_url = ep.full_url
                    break

        if not chat_url:
            console.print("  [dim]⏭ 未找到 Chat 端点，跳过提示词提取[/dim]")
            self._phase_reports.append(PhaseReport(
                phase_name="Phase 3 - 提示词提取",
                phase_id="prompt_extraction",
                status="skipped",
                summary="未找到 Chat 端点",
            ))
            return

        try:
            result = await self._prompt_extractor.extract(
                chat_url=chat_url,
                model_name=self.profile.target.model_name or "",
                extra_headers=self.auth_headers if self.auth_headers else None,
            )

            # 风险面板
            risk_color = "red" if result.risk_score >= 0.7 else "yellow" if result.risk_score >= 0.3 else "green"
            console.print(
                f"  [{risk_color}]风险评分: {result.risk_score:.0%} "
                f"({'严重' if result.risk_score >= 0.7 else '中危' if result.risk_score >= 0.3 else '低危'})[/{risk_color}]"
            )
            self.add_finding(
                "Phase 3 · 提示词提取",
                "critical" if result.risk_score >= 0.7 else "high" if result.risk_score >= 0.3 else "low",
                f"💉 提示词注入风险评分: {result.risk_score:.0%}",
                f"等级: {'严重' if result.risk_score >= 0.7 else '中危' if result.risk_score >= 0.3 else '低危'}",
                {"risk_score": result.risk_score},
            )

            if result.system_prompt_extracted:
                console.print(
                    f"  [red]🚨 系统提示词泄露: {len(result.system_prompt_fragments)} 个片段 "
                    f"(置信度 {result.system_prompt_confidence:.0%})[/red]"
                )
                for frag in result.system_prompt_fragments[:3]:
                    console.print(f"    [dim]  • {frag[:120]}...[/dim]")
                self.add_finding(
                    "Phase 3 · 提示词提取",
                    "critical",
                    f"🚨 系统提示词泄露: {len(result.system_prompt_fragments)} 个片段",
                    f"置信度 {result.system_prompt_confidence:.0%}; 片段示例: {result.system_prompt_fragments[0][:80] if result.system_prompt_fragments else ''}",
                    {"fragments_count": len(result.system_prompt_fragments), "confidence": result.system_prompt_confidence},
                )

            if result.tools_extracted:
                console.print(
                    f"  [yellow]⚠ 工具清单: {result.tools_count} 个工具[/yellow]"
                )
                for tool in result.tools_extracted[:5]:
                    console.print(f"    [dim]  • {tool}[/dim]")
                self.add_finding(
                    "Phase 3 · 提示词提取",
                    "high",
                    f"⚠ 工具清单泄露: {result.tools_count} 个工具",
                    f"工具列表: {', '.join(result.tools_extracted[:5])}",
                    {"tools": result.tools_extracted[:10]},
                )

            if result.guardrail_detected:
                console.print(
                    f"  [dim]🛡 Guardrail 规则: {len(result.guardrail_rules)} 条[/dim]"
                )

            if result.key_prefix_leaked:
                console.print(
                    f"  [red]🔑 密钥前缀泄露: {', '.join(result.key_prefixes)}[/red]"
                )
                self.add_finding(
                    "Phase 3 · 提示词提取",
                    "critical",
                    f"🔑 密钥前缀泄露: {', '.join(result.key_prefixes)}",
                    "从系统提示词中提取到 API Key 前缀, 可用于凭证预测",
                    {"prefixes": result.key_prefixes},
                )

            if result.knowledge_cutoff:
                console.print(f"  [dim]📅 知识截止: {result.knowledge_cutoff}[/dim]")
                self.add_finding(
                    "Phase 3 · 提示词提取",
                    "info",
                    f"📅 知识截止: {result.knowledge_cutoff}",
                    f"模型能力: {', '.join(result.capabilities[:3]) if result.capabilities else 'N/A'}",
                    {"knowledge_cutoff": result.knowledge_cutoff},
                )

            if result.capabilities:
                console.print(
                    f"  [dim]💡 能力: {', '.join(result.capabilities[:4])}[/dim]"
                )

            if not result.extraction_success:
                console.print("  [green]✅ 目标对提示词注入防护良好[/green]")

            # 应用到 profile
            self.profile.prompt_extraction = PromptExtractionInfo(
                system_prompt_fragments=result.system_prompt_fragments,
                system_prompt_extracted=result.system_prompt_extracted,
                system_prompt_confidence=result.system_prompt_confidence,
                tools_extracted=result.tools_extracted,
                tools_count=result.tools_count,
                guardrail_rules=result.guardrail_rules,
                guardrail_detected=result.guardrail_detected,
                capabilities=result.capabilities,
                knowledge_cutoff=result.knowledge_cutoff,
                model_identity=result.model_identity,
                key_prefixes=result.key_prefixes,
                key_prefix_leaked=result.key_prefix_leaked,
                extraction_success=result.extraction_success,
                risk_score=result.risk_score,
                all_responses=result.all_responses,
                errors=result.errors,
                summary=result.summary,
                recommendations=result.recommendations,
            )

            # 补充模型信息到 target
            if result.knowledge_cutoff:
                self.profile.target.model_name = (
                    f"{self.profile.target.model_name} (截止: {result.knowledge_cutoff})"
                    if self.profile.target.model_name
                    else f"截止: {result.knowledge_cutoff}"
                )

            # 生成阶段报告
            key_items = []
            if result.system_prompt_extracted:
                key_items.append(f"系统提示词泄露 ({len(result.system_prompt_fragments)}片段)")
            if result.tools_extracted:
                key_items.append(f"提取到 {result.tools_count} 个工具")
            if result.key_prefix_leaked:
                key_items.append("密钥前缀泄露")
            if result.knowledge_cutoff:
                key_items.append(f"知识截止: {result.knowledge_cutoff}")
            if result.capabilities:
                key_items.append(f"能力: {', '.join(result.capabilities[:3])}")

            self._phase_reports.append(PhaseReport(
                phase_name="Phase 3 - 提示词提取",
                phase_id="prompt_extraction",
                status="completed",
                findings_count=len(result.system_prompt_fragments) + result.tools_count + len(result.guardrail_rules),
                key_items=key_items,
                summary=result.summary,
                raw_data={"risk_score": result.risk_score, "extraction_success": result.extraction_success},
            ))

        except Exception as e:
            console.print(f"  [yellow]⚠ 提示词提取异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase3 prompt_extraction: {e}")
            self._phase_reports.append(PhaseReport(
                phase_name="Phase 3 - 提示词提取",
                phase_id="prompt_extraction",
                status="failed",
                summary=str(e),
            ))

    async def _phase5_behavior_mapping(self):
        """Phase 5 (用户视角): 行为测绘 — 综合安全评估 + 攻击路线图。

        综合分析所有侦察数据，输出：
        - 7 维度安全评分
        - 最佳攻击入口
        - 优先级排序的攻击向量
        - PyRIT 编排器映射
        - Markdown 详细报告
        """
        console.print()
        console.print("[bold cyan]🎯 Phase 5: 行为测绘 — 攻击路线图[/bold cyan]")

        try:
            result = self._behavior_mapper.map(self.profile)

            # 综合评分
            score_color = "red" if result.overall_label == "critical" else (
                "yellow" if result.overall_label in ("high", "medium") else "green"
            )
            console.print(
                f"  [{score_color}]综合安全评分: {result.overall_security_score:.1f}/10 "
                f"({result.overall_label.upper()})[/{score_color}]"
            )
            self.add_finding(
                "Phase 5 · 行为测绘",
                "critical" if result.overall_label in ("critical", "high") else "medium" if result.overall_label == "medium" else "low",
                f"🎯 综合安全评分: {result.overall_security_score:.1f}/10 ({result.overall_label.upper()})",
                f"最弱边界: {result.weakest_boundary[:120] if result.weakest_boundary else 'N/A'}",
                {"score": result.overall_security_score, "label": result.overall_label},
            )

            # 最弱边界
            console.print(
                f"  [yellow]⚠ 最弱安全边界: {result.weakest_boundary}[/yellow]"
            )

            # 攻击向量
            console.print(f"  [bold]📋 推荐攻击向量 ({len(result.attack_vectors)} 条):[/bold]")
            priority_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            for i, av in enumerate(result.attack_vectors[:5]):
                icon = priority_icons.get(av.priority, "⚪")
                console.print(
                    f"    {icon} #{i+1} [{av.priority.upper()}] {av.name} "
                    f"[dim](成功率 {av.success_probability:.0%})[/dim]"
                )
                self.add_finding(
                    "Phase 5 · 行为测绘",
                    "critical" if av.priority == "critical" else "high" if av.priority == "high" else "medium",
                    f"{icon} 攻击向量 #{i+1}: {av.name}",
                    f"优先级: {av.priority.upper()}; 成功率: {av.success_probability:.0%}; PyRIT: {av.pyrit_orchestrator}",
                    {"name": av.name, "priority": av.priority, "success_rate": av.success_probability, "pyrit": av.pyrit_orchestrator},
                )

            # 攻击入口
            console.print(f"  [green]🎯 {result.target_attack_entry[:150]}...[/green]")

            # 保存 Markdown 报告
            report_path = str(self.output_dir / "behavior_map_report.md")
            try:
                self.output_dir.mkdir(parents=True, exist_ok=True)
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(result.detailed_report)
                console.print(f"  [dim]📄 详细报告已保存: {report_path}[/dim]")
            except Exception:
                pass

            # 应用到 profile
            self.profile.behavior_map = BehaviorMapInfo(
                overall_security_score=result.overall_security_score,
                overall_label=result.overall_label,
                weakness_scores=[
                    {"dimension": ws.dimension, "score": ws.score, "evidence": ws.evidence, "details": ws.details}
                    for ws in result.weakness_scores
                ],
                critical_findings=result.critical_findings,
                weakest_boundary=result.weakest_boundary,
                attack_vectors=[
                    {
                        "name": av.name, "priority": av.priority,
                        "description": av.description,
                        "pyrit_orchestrator": av.pyrit_orchestrator,
                        "success_probability": av.success_probability,
                        "preconditions": av.preconditions,
                    }
                    for av in result.attack_vectors
                ],
                target_attack_entry=result.target_attack_entry,
                bypass_feasibility=result.bypass_feasibility,
                bypass_methods=result.bypass_methods,
                summary=result.summary,
                detailed_report=result.detailed_report,
            )

            # 生成阶段报告
            key_items = [
                f"综合评分 {result.overall_security_score:.1f}/10 ({result.overall_label})",
                f"最弱边界: {result.weakest_boundary[:80]}",
            ]
            for av in result.attack_vectors[:3]:
                key_items.append(f"{av.priority}: {av.name}")

            self._phase_reports.append(PhaseReport(
                phase_name="Phase 5 - 行为测绘",
                phase_id="behavior_mapping",
                status="completed",
                findings_count=len(result.attack_vectors) + len(result.critical_findings),
                key_items=key_items,
                summary=result.summary,
                raw_data={
                    "overall_security_score": result.overall_security_score,
                    "overall_label": result.overall_label,
                    "attack_vectors_count": len(result.attack_vectors),
                },
            ))

        except Exception as e:
            console.print(f"  [yellow]⚠ 行为测绘异常: {e}[/yellow]")
            self.profile.artifacts.errors.append(f"Phase5 behavior_mapping: {e}")
            self._phase_reports.append(PhaseReport(
                phase_name="Phase 5 - 行为测绘",
                phase_id="behavior_mapping",
                status="failed",
                summary=str(e),
            ))

    async def _phase6_build_profile(self):
        """Phase 6: 组装并清洗 Profile + 生成分阶段报告。"""
        console.print()
        console.print("[bold cyan]📦 Phase 6: 组装 Profile + 报告[/bold cyan]")

        # 去重端点
        seen = set()
        unique_eps = []
        for ep in self.profile.api_endpoints:
            key = (ep.path, ep.method)
            if key not in seen:
                seen.add(key)
                unique_eps.append(ep)
        self.profile.api_endpoints = unique_eps

        # 统计
        chat_eps = [ep for ep in self.profile.api_endpoints if ep.is_chat_endpoint]
        if chat_eps:
            console.print(f"  [green]  Chat 端点: {len(chat_eps)}[/green]")
        console.print(f"  [dim]  总端点: {len(self.profile.api_endpoints)}[/dim]")
        console.print(f"  [dim]  动态路由: {len(self.profile.dynamic_routes)}[/dim]")

        # 生成各阶段完整报告
        self._build_all_phase_reports()

    def _build_all_phase_reports(self):
        """汇总所有阶段的报告，写入 profile.phase_reports。"""
        # Phase 1: 资产发现
        endpoints_by_cat = {}
        for ep in self.profile.api_endpoints:
            cat = ep.category or "other"
            endpoints_by_cat[cat] = endpoints_by_cat.get(cat, 0) + 1

        debug_count = sum(1 for ep in self.profile.api_endpoints if ep.category == "debug")
        agent_card = getattr(self.profile.rag_probe, "agent_card_discovered", False)
        phase1_items = [
            f"API 端点: {len(self.profile.api_endpoints)} 个",
            f"Chat 端点: {sum(1 for ep in self.profile.api_endpoints if ep.is_chat_endpoint)} 个",
            f"动态路由: {len(self.profile.dynamic_routes)} 个",
        ]
        if debug_count > 0:
            phase1_items.append(f"调试接口: {debug_count} 个 OPEN")
        if agent_card:
            phase1_items.append(f"Agent 卡片: 已发现")
        if self.profile.js_sdk.total_matches > 0:
            phase1_items.append(f"JS SDK 引用: {self.profile.js_sdk.total_matches} 个")

        self._phase_reports.insert(0, PhaseReport(
            phase_name="Phase 1 - 资产发现",
            phase_id="asset_discovery",
            status="completed",
            findings_count=len(self.profile.api_endpoints) + len(self.profile.dynamic_routes),
            key_items=phase1_items,
            summary=f"发现 {len(self.profile.api_endpoints)} 个端点, {len(self.profile.dynamic_routes)} 条动态路由, "
                    f"{'包含调试/Agent接口' if debug_count or agent_card else '未发现敏感接口'}",
        ))

        # Phase 2: 模型指纹
        mp = self.profile.model_probe
        pe = self.profile.prompt_extraction
        phase2_items = []
        if mp.model_name:
            phase2_items.append(f"模型: {mp.model_name} (置信度 {mp.confidence:.0%})")
        if mp.framework and mp.framework != "unknown":
            phase2_items.append(f"框架: {mp.framework}")
        if pe.knowledge_cutoff:
            phase2_items.append(f"知识截止: {pe.knowledge_cutoff}")
        if pe.capabilities:
            phase2_items.append(f"能力: {len(pe.capabilities)} 项")
        if pe.guardrail_detected:
            phase2_items.append(f"Guardrail: {len(pe.guardrail_rules)} 条")

        self._phase_reports.insert(1, PhaseReport(
            phase_name="Phase 2 - 模型指纹",
            phase_id="model_fingerprint",
            status="completed" if mp.model_name else "completed",
            findings_count=len(phase2_items),
            key_items=phase2_items or ["模型指纹探测完成（无显著发现）"],
            summary=f"识别模型: {mp.model_name or '未知'}, 框架: {mp.framework or '未知'}, "
                    f"知识截止: {pe.knowledge_cutoff or '未知'}",
        ))

        # Phase 4: 防护探测
        waf = self.profile.waf
        rl = self.profile.rate_limit
        phase4_items = []
        if waf.waf_count > 0:
            phase4_items.append(f"WAF: {waf.summary}")
        else:
            phase4_items.append("WAF: 未检测到")
        if rl.has_rate_limit:
            phase4_items.append(f"速率限制: RPM {rl.rpm_limit or '未知'}, 429 × {rl.total_429s}")
        else:
            phase4_items.append("速率限制: 未触发")
        if waf.implications:
            phase4_items.append(f"绕过建议: 已生成")

        idx = 3  # after Phase 3 (prompt_extraction) at index 2
        self._phase_reports.insert(idx, PhaseReport(
            phase_name="Phase 4 - 防护探测",
            phase_id="defense_detection",
            status="completed",
            findings_count=waf.waf_count + (1 if rl.has_rate_limit else 0),
            key_items=phase4_items,
            summary=f"WAF: {'检测到 ' + str(waf.waf_count) + ' 层' if waf.waf_count else '无'}, "
                    f"速率限制: {'有' if rl.has_rate_limit else '无'}",
        ))

        # 保存 phase_reports 到 profile
        self.profile.phase_reports = self._phase_reports

        # 保存 JSON 摘要报告
        self._save_phase_reports_json()

    def _save_phase_reports_json(self):
        """保存分阶段报告 JSON 文件。"""
        try:
            report_data = {
                "target": self.target_url,
                "generated_at": self.profile.meta.generated_at,
                "version": "1.3",
                "phases": [
                    {
                        "id": pr.phase_id,
                        "name": pr.phase_name,
                        "status": pr.status,
                        "findings_count": pr.findings_count,
                        "key_items": pr.key_items,
                        "summary": pr.summary,
                    }
                    for pr in self._phase_reports
                ],
            }
            report_path = str(self.output_dir / "phase_summary.json")
            import json
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            console.print(f"  [dim]📋 阶段报告: {report_path}[/dim]")
        except Exception:
            pass

    def _save_profile(self) -> str:
        """保存 target_profile.json 到输出目录。"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"target_profile_{self._safe_filename(self.target_url)}.json"
        filepath = self.output_dir / filename
        return self.profile.save(str(filepath))

    @staticmethod
    def _safe_filename(url: str) -> str:
        """从 URL 生成安全文件名。"""
        import re
        safe = re.sub(r"https?://", "", url)
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", safe)
        return safe[:80]

    async def cleanup(self):
        """清理资源。"""
        if self._browser:
            await self._browser.stop()
