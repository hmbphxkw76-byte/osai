"""
SPA 路由分析器 — 识别前端框架、路由模式和动态路由。
"""

from __future__ import annotations

import asyncio
import re

from rich.console import Console

from recon.schema import SpaInfo, SpaFramework, RouterMode

console = Console()


# 框架指纹数据库
_FRAMEWORK_FINGERPRINTS = {
    SpaFramework.REACT: {
        "globals": ["React", "__REACT_DEVTOOLS_GLOBAL_HOOK__", "react-dom", "react.development"],
        "markers": ['data-reactroot', 'data-reactid', '_reactRootContainer'],
        "bundles": ["react", "react-dom", "main.chunk"],
        "api_patterns": [],
    },
    SpaFramework.VUE: {
        "globals": ["Vue", "__VUE_DEVTOOLS_GLOBAL_HOOK__", "__vue__"],
        "markers": ['data-v-', '[data-v-', 'vue-app', '#app'],
        "bundles": ["vue", "vue-router", "vuex", "pinia"],
        "api_patterns": [],
    },
    SpaFramework.ANGULAR: {
        "globals": ["ng", "angular", "Zone"],
        "markers": ['ng-version', '_nghost', '_ngcontent', 'app-root'],
        "bundles": ["main.", "polyfills.", "runtime.", "vendor."],
        "api_patterns": [],
    },
    SpaFramework.SVELTE: {
        "globals": ["__svelte"],
        "markers": ['svelte-'],
        "bundles": ["svelte"],
        "api_patterns": [],
    },
    SpaFramework.NEXT: {
        "globals": ["__NEXT_DATA__", "__NEXT", "next"],
        "markers": ['__NEXT_DATA__', '__next', '/_next/'],
        "bundles": ["_next/static", "webpack-" ],
        "api_patterns": ["/api/"],
    },
    SpaFramework.NUXT: {
        "globals": ["__NUXT__", "$nuxt"],
        "markers": ['__NUXT__', 'nuxt-app'],
        "bundles": ["_nuxt/"],
        "api_patterns": [],
    },
}

# 已知 API 路径模式（用于从 JS 中提取）
_API_PATH_PATTERNS = [
    # URL 字符串模式
    r'["\']((?:https?:)?//[^"\']*/api/[^"\']+)["\']',
    r'["\']((?:https?:)?//[^"\']*/v\d+/[^"\']+)["\']',
    r'["\'](/api/[^"\']+)["\']',
    r'["\'](/v\d+/[^"\']+)["\']',
    # fetch/axios 调用模式
    r'(?:fetch|axios|request)\s*\(\s*["\']([^"\']+)["\']',
    r'(?:baseURL|BASE_URL|apiUrl|API_URL)\s*[:=]\s*["\']([^"\']+)["\']',
    # 路由定义
    r'(?:path|route)\s*:\s*["\']/(\w+)/(\w+)/(\w+)["\']',
    r'["\']/(\w+)/(\w+)/(\w+)["\']\s*[,;}\n]',
]


class SpaRouterAnalyzer:
    """SPA 框架检测与路由提取。

    通过执行 Playwright JS 代码检测前端框架，
    并从页面源码和 JS bundle 中提取 API 端点和路由模式。
    """

    def __init__(self, browser_manager):
        self._browser = browser_manager

    async def analyze(self, page) -> SpaInfo:
        """分析页面，返回 SpaInfo。

        检测：框架类型、路由模式、API base URL、动态路由。
        """
        info = SpaInfo()

        # 1. 检测是否为 SPA
        is_spa = await page.evaluate("""
            () => {
                // 检查 root div
                const rootElem = document.getElementById('root')
                    || document.getElementById('app')
                    || document.getElementById('__next')
                    || document.getElementById('__nuxt');
                if (rootElem) return true;

                // 检查框架全局变量
                const frameworkGlobals = [
                    'React', '__REACT_DEVTOOLS_GLOBAL_HOOK__',
                    'Vue', '__VUE_DEVTOOLS_GLOBAL_HOOK__',
                    'ng', 'angular',
                    '__svelte', '__NEXT_DATA__', '__NUXT__',
                ];
                for (const g of frameworkGlobals) {
                    if (window[g]) return true;
                }

                // 检查 router
                if (window.__reactRouter || window.$router || window.router) return true;

                return false;
            }
        """)
        info.is_spa = is_spa

        if not is_spa:
            console.print("  [dim]非 SPA，跳过框架分析[/dim]")
            return info

        # 2. 识别框架
        info.framework = await self._detect_framework(page)

        # 3. 识别路由模式
        info.router_mode = await self._detect_router_mode(page)

        # 4. 提取 JS bundle URLs
        info.js_bundle_urls = await self._extract_js_bundles(page)

        # 5. 从 JS 提取 API base URL
        info.api_base_url = await self._extract_api_base(page)

        # 6. 提取路由和端点
        js_content = await self._fetch_js_bundles(page, info.js_bundle_urls)
        endpoints, routes = self._extract_from_js(js_content)
        info.extracted_endpoints_count = len(endpoints)
        info.extracted_routes_count = len(routes)

        return info

    async def _detect_framework(self, page) -> str:
        """检测前端框架。"""
        detect_script = """
            () => {
                if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || window.React || document.querySelector('[data-reactroot]'))
                    return 'react';
                if (window.__VUE_DEVTOOLS_GLOBAL_HOOK__ || window.Vue || document.querySelector('[data-v-]') || document.querySelector('#app[data-v-]'))
                    return 'vue';
                if (window.ng || document.querySelector('[ng-version]') || document.querySelector('app-root'))
                    return 'angular';
                if (window.__svelte || document.querySelector('[svelte-]'))
                    return 'svelte';
                if (window.__NEXT_DATA__ || document.getElementById('__next'))
                    return 'nextjs';
                if (window.__NUXT__ || document.getElementById('__nuxt'))
                    return 'nuxt';
                return 'unknown';
            }
        """
        try:
            framework = await page.evaluate(detect_script)
            return framework or SpaFramework.UNKNOWN.value
        except Exception:
            return SpaFramework.UNKNOWN.value

    async def _detect_router_mode(self, page) -> str:
        """检测 SPA 路由模式。"""
        detect_script = """
            () => {
                const url = window.location.href;
                if (url.includes('#'))
                    return 'hash';
                if (window.history && window.history.pushState)
                    return 'history';
                if (window.__reactRouter || window.$router || window.router)
                    return 'history';
                return 'unknown';
            }
        """
        try:
            mode = await page.evaluate(detect_script)
            return mode or RouterMode.UNKNOWN.value
        except Exception:
            return RouterMode.UNKNOWN.value

    async def _extract_js_bundles(self, page) -> list[str]:
        """提取页面中所有 JS bundle URL。"""
        extract_script = """
            () => {
                const scripts = Array.from(document.querySelectorAll('script[src]'));
                return scripts.map(s => s.src).filter(src =>
                    !src.includes('googletagmanager') &&
                    !src.includes('google-analytics') &&
                    !src.includes('clarity.ms')
                );
            }
        """
        try:
            bundles = await page.evaluate(extract_script)
            return bundles or []
        except Exception:
            return []

    async def _extract_api_base(self, page) -> str:
        """从页面全局变量中提取 API base URL。"""
        extract_script = """
            () => {
                // 尝试从常见全局变量获取
                const candidates = [
                    window.API_BASE_URL,
                    window.API_URL,
                    window.VITE_API_URL,
                    window.REACT_APP_API_URL,
                    window.NEXT_PUBLIC_API_URL,
                ];
                for (const c of candidates) {
                    if (c && typeof c === 'string') return c;
                }

                // 从 __NEXT_DATA__ 提取
                if (window.__NEXT_DATA__ && window.__NEXT_DATA__.props) {
                    const props = window.__NEXT_DATA__.props;
                    if (props.pageProps && props.pageProps.apiUrl) return props.pageProps.apiUrl;
                }

                return '';
            }
        """
        try:
            return await page.evaluate(extract_script) or ""
        except Exception:
            return ""

    async def _fetch_js_bundles(self, page, bundle_urls: list[str], max_bundles: int = 5) -> str:
        """获取并解析 JS bundle 内容。"""
        all_content = []

        for url in bundle_urls[:max_bundles]:
            try:
                content = await page.evaluate(f"""
                    async () => {{
                        try {{
                            const resp = await fetch('{url}');
                            return await resp.text();
                        }} catch(e) {{
                            return '';
                        }}
                    }}
                """)
                if content:
                    all_content.append(content[:50000])  # 每个 bundle 截断 50KB
            except Exception:
                pass

        return "\n".join(all_content)

    def _extract_from_js(self, js_content: str) -> tuple[list[str], list[str]]:
        """从 JS 内容中提取 API 端点路径和路由模式。

        Returns:
            (api_endpoints, route_patterns)
        """
        if not js_content:
            return [], []

        api_endpoints = set()
        route_patterns = set()

        for pattern in _API_PATH_PATTERNS:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = "/".join(filter(None, match))
                match = match.strip().strip('"\'')
                # 只保留 API 相关的路径
                if "/api/" in match or "/v1/" in match or "/v2/" in match:
                    api_endpoints.add(match)
                elif match.startswith("/") and len(match) > 2:
                    route_patterns.add(match)

        # 动态路径检测（含 :param 或 {param} 的路径）
        dynamic_patterns = re.findall(
            r'["\'](/(?:\w+/)*(?::\w+|\{\w+\})(?:/\w+)*)["\']',
            js_content,
        )
        for dp in dynamic_patterns:
            route_patterns.add(dp)

        return list(api_endpoints), list(route_patterns)
