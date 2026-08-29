"""璁よ瘉鐘舵€佺鐞嗗櫒 鈥?Token 鍒锋柊 + 浼氳瘽淇濇椿 + 澶氱鎴锋帰娴?+ CSRF 杞崲銆?

瀛︽湳渚濇嵁:
    - Heroux et al. (arXiv:2403.04206) 搂3.2 鈥?瓒呮椂/璁よ瘉澶辨晥鎭㈠绛栫暐:
      璁よ瘉澶辨晥涓嶅簲缁堟鏀诲嚮, 搴斿皾璇曟仮澶嶅悗缁х画, 鎭㈠澶辫触鎵嶉檷绾с€?
    - Greshake et al. (arXiv:2302.12173) 搂4 鈥?淇′换閾惧埄鐢?
      璁よ瘉 token 鏄俊浠婚摼鐨勪竴鐜? 鍙€氳繃闂存帴娉ㄥ叆鑾峰彇鎴栧埛鏂般€?
    - OWASP WSTG-ATHN-01 鈥?璁よ瘉缁曡繃娴嬭瘯鏍囧噯銆?
    - OWASP API Security Top 10 (2025) API1 (BOLA) / API3 (BOPLA):
      澶氱鎴峰満鏅笅鐨勬潈闄愯竟鐣屾帰娴嬨€?

璁捐鍘熷垯 (Rule 2: 澧炲己灞? 涓嶆浛鎹?:
    鏈ā鍧楁槸鑳舵按灞傚寮? 涓嶆浛鎹换浣?PyRIT 鍘熺敓缁勪欢銆?
    - 璁よ瘉妫€娴? 闈欐€佸垎鏋?Burp 璇锋眰 headers
    - 璁よ瘉鎭㈠: 浣跨敤 httpx 鐩存帴鍙戦€?HTTP 璇锋眰 (闈?prompt 浜や簰)
    - 澶氱鎴锋帰娴? 淇敼 tenant header 鍚庨噸鏂板彂閫佽姹?
    - CSRF 杞崲: 浠庡搷搴?headers 涓彁鍙栨柊 token

PyRIT 璁捐鍩熻竟鐣?(Rule 2):
    璁よ瘉鎭㈠浣跨敤 httpx 鐩存帴鍙戦€?HTTP 璇锋眰 (鐧诲綍/鍒锋柊绔偣),
    杩欎笉鏄?LLM prompt 浜や簰, 灞炰簬 HTTP 鍗忚灞傛搷浣溿€?
    涓嶄娇鐢?HTTPTarget (涓嶉渶瑕?{PROMPT} 鍗犱綅绗?銆?
    绫讳技 MCP JSON-RPC 鏋氫妇鐨勪緥澶? httpx 鏄?PyRIT 宸叉湁渚濊禆銆?
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# JWT 瑙ｇ爜鎵€闇€鐨?base64url padding 琛ラ綈
_B64_PAD = "="


@dataclass
class AuthState:
    """璁よ瘉鐘舵€佸揩鐓?鈥?璐┛鏁翠釜鏀诲嚮鐢熷懡鍛ㄦ湡鐨勮璇佷俊鎭€?

    灞炴€?
        auth_type: 璁よ瘉绫诲瀷 (cookie / bearer / jwt / api_key / none)銆?
        raw_headers: 鍘熷璁よ瘉 header 鍒楄〃 (淇濇寔椤哄簭)銆?
        token_value: 鎻愬彇鐨?token 鍊?(Bearer xxx 涓殑 xxx 閮ㄥ垎)銆?
        token_expiry: 棰勪及杩囨湡鏃堕棿 (Unix timestamp, None = 鏈煡)銆?
        refresh_endpoint: token 鍒锋柊绔偣 (濡?/api/auth/refresh)銆?
        refresh_method: 鍒锋柊璇锋眰鏂规硶 (榛樿 POST)銆?
        tenant_id: 褰撳墠绉熸埛 ID (濡備粠 JWT payload 鎴栬矾寰勪腑鎻愬彇)銆?
        tenant_header: 绉熸埛 header 鍚?(濡?X-Tenant-Id, X-Org-Id)銆?
        csrf_token: 褰撳墠 CSRF token 鍊笺€?
        csrf_header: CSRF header 鍚?(榛樿 X-CSRF-Token)銆?
        refresh_count: 宸叉墽琛岃璇佹仮澶嶆鏁般€?
        max_refreshes: 鏈€澶ф仮澶嶆鏁?(榛樿 3)銆?
    """

    auth_type: str = "none"
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    token_value: str | None = None
    token_expiry: float | None = None
    refresh_endpoint: str | None = None
    refresh_method: str = "POST"
    tenant_id: str | None = None
    tenant_header: str | None = None
    csrf_token: str | None = None
    csrf_header: str = "X-CSRF-Token"
    refresh_count: int = 0
    max_refreshes: int = 3


class AuthStateManager:
    """璁よ瘉鐘舵€佺鐞?鈥?妫€娴嬨€佹仮澶嶃€佷繚娲汇€佸绉熸埛鎺㈡祴銆?

    鐢熷懡鍛ㄦ湡:
        1. detect_auth_type(): 浠?Burp 璇锋眰闈欐€佸垎鏋愯璇佺被鍨?
        2. (鏀诲嚮鎵ц涓? 401/403 瑙﹀彂 try_recover_auth()
        3. try_recover_auth(): 灏濊瘯 token 鍒锋柊 / 閲嶆柊鐧诲綍 / 鍖垮悕闄嶇骇
        4. try_tenant_switch(): 403 鏃跺皾璇曞垏鎹㈢鎴?ID
        5. update_csrf_token(): 浠庡搷搴斾腑鎻愬彇鏂?CSRF token

    浣跨敤鏂瑰紡:
        manager = AuthStateManager()
        auth_state = await manager.detect_auth_type(parsed)
        # ... 鏀诲嚮鎵ц涓?401 ...
        recovered = await manager.try_recover_auth(auth_state)
        if recovered:
            new_headers = await manager.refresh_headers(auth_state)
    """

    def __init__(self, *, max_refreshes: int = 3) -> None:
        """鍒濆鍖栬璇佺姸鎬佺鐞嗗櫒銆?

        Args:
            max_refreshes: 鏈€澶ц璇佹仮澶嶆鏁?(榛樿 3)銆?
        """
        self._max_refreshes = max_refreshes

    async def detect_auth_type(self, parsed: Any) -> AuthState:
        """浠?Burp 璇锋眰闈欐€佸垎鏋愯璇佺被鍨嬪拰鍙傛暟銆?

        妫€娴嬬瓥鐣?(鎸変紭鍏堢骇):
            1. Authorization: Bearer xxx 鈫?JWT (瑙ｇ爜 exp) 鎴?Bearer Token
            2. Cookie: session_id / JSESSIONID / PHPSESSID 鈫?Cookie-based
            3. X-API-Key: xxx 鈫?API Key
            4. 鏃犺璇佸ご 鈫?灏濊瘯鍖垮悕璁块棶

        JWT exp 瑙ｇ爜:
            瑙ｇ爜 JWT payload (涓嶉獙绛?, 鎻愬彇 exp 瀛楁銆?
            棰勪及杩囨湡鏃堕棿 = exp - 60s (鎻愬墠 1 鍒嗛挓鍒锋柊)銆?
            瀛︽湳渚濇嵁: RFC 7519 搂4.1.4 鈥?exp 鏄?JWT 鏍囧噯澹版槑銆?

        Args:
            parsed: ParsedBurpRequest 瀹炰緥銆?

        Returns:
            AuthState 璁よ瘉鐘舵€佸揩鐓с€?
        """
        state = AuthState(max_refreshes=self._max_refreshes)

        if not hasattr(parsed, "headers"):
            return state

        headers = parsed.headers
        state.raw_headers = list(getattr(parsed, "raw_headers", []))

        # 鈹€鈹€ 1. Authorization: Bearer 鈹€鈹€
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
            state.token_value = token
            state.auth_type = "bearer"

            # 灏濊瘯瑙ｇ爜涓?JWT
            jwt_payload = _decode_jwt_payload(token)
            if jwt_payload is not None:
                state.auth_type = "jwt"
                exp = jwt_payload.get("exp")
                if exp and isinstance(exp, (int, float)):
                    # 鎻愬墠 60 绉掑埛鏂?(閬垮厤鏀诲嚮杩囩▼涓繃鏈?
                    state.token_expiry = float(exp) - 60.0
                    logger.info(
                        "JWT detected: exp=%s, expiry_in=%.0fs",
                        exp,
                        state.token_expiry - time.time(),
                    )

                # 浠?JWT payload 鎻愬彇绉熸埛淇℃伅
                tenant = (
                    jwt_payload.get("tenant_id")
                    or jwt_payload.get("org_id")
                    or jwt_payload.get("organization")
                    or jwt_payload.get("workspace")
                )
                if tenant:
                    state.tenant_id = str(tenant)
                    logger.info("JWT tenant detected: %s", state.tenant_id)

        # 鈹€鈹€ 2. Cookie-based 鈹€鈹€
        elif "cookie" in headers:
            cookie_str = headers["cookie"]
            state.auth_type = "cookie"

            # 妫€娴?session 绫诲瀷
            if re.search(r"session[_-]?id", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: session_id detected")
            elif re.search(r"JSESSIONID", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: JSESSIONID detected")
            elif re.search(r"PHPSESSID", cookie_str, re.IGNORECASE):
                logger.info("Cookie auth: PHPSESSID detected")

            # Cookie 杩囨湡鏃堕棿鏈煡 (鏃犳硶浠?cookie 鍊兼帹鏂?
            state.token_value = cookie_str

        # 鈹€鈹€ 3. X-API-Key 鈹€鈹€
        elif headers.get("x-api-key"):
            state.auth_type = "api_key"
            state.token_value = headers["x-api-key"]
            logger.info("API Key auth detected")

        else:
            state.auth_type = "none"
            logger.info("No authentication headers detected 鈥?anonymous access")

        # 鈹€鈹€ 妫€娴嬬鎴?header 鈹€鈹€
        for h_name, h_value in state.raw_headers:
            h_lower = h_name.lower()
            if h_lower in ("x-tenant-id", "x-org-id", "x-organization", "x-workspace"):
                state.tenant_header = h_name
                state.tenant_id = h_value
                logger.info("Tenant header detected: %s=%s", h_name, h_value)
                break

        # 鈹€鈹€ 妫€娴?CSRF token header 鈹€鈹€
        for h_name, h_value in state.raw_headers:
            h_lower = h_name.lower()
            if h_lower in ("x-csrf-token", "x-xsrf-token", "csrf-token"):
                state.csrf_header = h_name
                state.csrf_token = h_value
                logger.info("CSRF token detected in header: %s", h_name)
                break

        return state

    async def try_recover_auth(
        self,
        auth_state: AuthState,
        *,
        host: str = "",
        use_tls: bool = True,
    ) -> bool:
        """璁よ瘉澶辨晥鍚庡皾璇曟仮澶嶃€?

        鎭㈠绛栫暐 (3 灞?fallback):
            1. Token 鍒锋柊: POST refresh_endpoint 鈫?鑾峰彇鏂?token
            2. 閲嶆柊鐧诲綍: 浣跨敤鐜鍙橀噺涓殑鍑瘉閲嶆柊鐧诲綍
            3. 鍖垮悕闄嶇骇: 鍘绘帀璁よ瘉澶? 灏濊瘯鍖垮悕璁块棶

        瀛︽湳渚濇嵁:
            - Heroux et al. (arXiv:2403.04206) 搂3.2 鈥?鎭㈠绛栫暐
            - RFC 6749 搂6 鈥?OAuth 2.0 Token Refresh

        Args:
            auth_state: 褰撳墠璁よ瘉鐘舵€併€?
            host: 鐩爣 host (鐢ㄤ簬鏋勫缓鍒锋柊璇锋眰 URL)銆?
            use_tls: 鏄惁浣跨敤 TLS銆?

        Returns:
            True 濡傛灉鎭㈠鎴愬姛, False 濡傛灉鎵€鏈夌瓥鐣ュけ璐ャ€?
        """
        if auth_state.refresh_count >= auth_state.max_refreshes:
            logger.warning(
                "Auth recovery exhausted (max=%d), giving up",
                auth_state.max_refreshes,
            )
            return False

        auth_state.refresh_count += 1

        # 鈹€鈹€ 绛栫暐 1: Token 鍒锋柊 鈹€鈹€
        if auth_state.refresh_endpoint:
            success = await self._try_token_refresh(auth_state, host, use_tls)
            if success:
                logger.info("Auth recovered via token refresh")
                return True

        # 鈹€鈹€ 绛栫暐 2: 閲嶆柊鐧诲綍 鈹€鈹€
        login_endpoint = os.environ.get("TARGET_LOGIN_ENDPOINT")
        login_user = os.environ.get("TARGET_LOGIN_USER")
        login_pass = os.environ.get("TARGET_LOGIN_PASS")
        if login_endpoint and login_user and login_pass:
            success = await self._try_relogin(
                auth_state, login_endpoint, login_user, login_pass, host, use_tls
            )
            if success:
                logger.info("Auth recovered via re-login")
                return True

        # 鈹€鈹€ 绛栫暐 3: 鍖垮悕闄嶇骇 鈹€鈹€
        # 鏌愪簺 Agent 绔偣鍙兘涓嶉渶瑕佽璇?(濡傚叕寮€ API)
        logger.info("Auth recovery failed, trying anonymous access")
        auth_state.auth_type = "none"
        auth_state.token_value = None
        auth_state.raw_headers = [
            (k, v) for k, v in auth_state.raw_headers
            if k.lower() not in ("authorization", "cookie", "x-api-key")
        ]
        return True  # 鍖垮悕闄嶇骇涓嶆槸鐪熸鐨勬仮澶? 浣嗗厑璁哥户缁皾璇?

    async def try_tenant_switch(
        self,
        auth_state: AuthState,
        *,
        new_tenant_id: str | None = None,
    ) -> AuthState | None:
        """澶氱鎴锋帰娴?鈥?灏濊瘯鍒囨崲绉熸埛 ID 缁曡繃 403銆?

        瀛︽湳渚濇嵁:
            - OWASP API1 (BOLA) 鈥?璺緞涓殑 tenant_id 鍙灇涓?
            - OWASP API3 (BOPLA) 鈥?鏉冮檺杈圭晫鎺㈡祴

        绛栫暐:
            1. 浠?JWT payload 鎴?header 涓彁鍙栧綋鍓?tenant_id
            2. 灏濊瘯鏋氫妇鍏朵粬 tenant_id (鏁板瓧閫掑 / 甯歌鍚嶇О)
            3. 鏇挎崲 tenant_header, 閲嶆柊鍙戦€佽姹?

        Args:
            auth_state: 褰撳墠璁よ瘉鐘舵€併€?
            new_tenant_id: 鎸囧畾鐨勬柊绉熸埛 ID (None = 鑷姩鏋氫妇)銆?

        Returns:
            鍒囨崲鍚庣殑 AuthState 鍓湰, 鎴?None 濡傛灉鏃犳硶鍒囨崲銆?
        """
        if not auth_state.tenant_header:
            logger.debug("No tenant header found, cannot switch tenant")
            return None

        # 鍒涘缓 auth_state 鍓湰
        import copy
        new_state = copy.deepcopy(auth_state)

        if new_tenant_id:
            # 浣跨敤鎸囧畾鐨勬柊绉熸埛 ID
            new_state.tenant_id = new_tenant_id
        elif auth_state.tenant_id:
            # 灏濊瘯鏁板瓧閫掑 (濡?org_001 鈫?org_002)
            num_match = re.search(r"(\d+)", auth_state.tenant_id)
            if num_match:
                current_num = int(num_match.group(1))
                prefix = auth_state.tenant_id[: num_match.start()]
                suffix = auth_state.tenant_id[num_match.end() :]
                num_width = len(num_match.group(1))

                new_num = current_num + 1
                new_state.tenant_id = f"{prefix}{new_num:0{num_width}d}{suffix}"
                logger.info(
                    "Tenant switch: %s 鈫?%s",
                    auth_state.tenant_id,
                    new_state.tenant_id,
                )
            else:
                logger.debug("Tenant ID has no numeric part, cannot enumerate")
                return None
        else:
            return None

        # 鏇存柊 raw_headers 涓殑 tenant header
        new_headers: list[tuple[str, str]] = []
        for k, v in new_state.raw_headers:
            if k.lower() == new_state.tenant_header.lower():
                new_headers.append((k, new_state.tenant_id))
            else:
                new_headers.append((k, v))
        new_state.raw_headers = new_headers

        return new_state

    def update_csrf_token(
        self,
        auth_state: AuthState,
        response_headers: dict[str, str],
        response_body: str = "",
    ) -> AuthState:
        """浠庡搷搴斾腑鎻愬彇鏂?CSRF token, 鏇存柊鍒?auth_state銆?

        鏌愪簺 Agent 搴旂敤姣忔鍝嶅簲閮借疆鎹?CSRF token:
            - Set-Cookie: csrf=xxx
            - X-CSRF-Token: xxx (鍝嶅簲 header)
            - 鍝嶅簲 JSON: {"csrf_token": "xxx"}

        Args:
            auth_state: 褰撳墠璁よ瘉鐘舵€併€?
            response_headers: HTTP 鍝嶅簲 headers銆?
            response_body: HTTP 鍝嶅簲浣?(鍙€? 鐢ㄤ簬浠?JSON 鎻愬彇)銆?

        Returns:
            鏇存柊鍚庣殑 AuthState (鍘熷湴淇敼 + 杩斿洖寮曠敤)銆?
        """
        # 浠庡搷搴?header 鎻愬彇
        for h_name, h_value in response_headers.items():
            h_lower = h_name.lower()
            if h_lower in ("x-csrf-token", "x-xsrf-token"):
                auth_state.csrf_token = h_value
                auth_state.csrf_header = h_name
                logger.info("CSRF token updated from response header: %s", h_name)
                return auth_state

        # 浠?Set-Cookie 鎻愬彇
        set_cookie = response_headers.get("set-cookie", "")
        if set_cookie:
            csrf_match = re.search(r"csrf[=:]([^\s;]+)", set_cookie, re.IGNORECASE)
            if csrf_match:
                auth_state.csrf_token = csrf_match.group(1)
                logger.info("CSRF token updated from Set-Cookie")
                return auth_state

        # 浠?JSON 鍝嶅簲浣撴彁鍙?
        if response_body:
            try:
                data = json.loads(response_body)
                if isinstance(data, dict):
                    for key in ("csrf_token", "csrf", "xsrf_token", "_token"):
                        if key in data:
                            auth_state.csrf_token = str(data[key])
                            logger.info("CSRF token updated from response body: %s", key)
                            return auth_state
            except (json.JSONDecodeError, TypeError):
                pass

        return auth_state

    def build_auth_headers(self, auth_state: AuthState) -> list[tuple[str, str]]:
        """鏍规嵁褰撳墠 auth_state 閲嶅缓璁よ瘉 headers銆?

        绛栫暐:
            1. 浠?raw_headers 涓哄熀纭€
            2. 濡傛灉 token_value 鏇存柊浜?鈫?鏇挎崲 Authorization header
            3. 濡傛灉 tenant_id 鏇存柊浜?鈫?鏇挎崲 tenant header
            4. 濡傛灉 csrf_token 鏇存柊浜?鈫?鏇挎崲 CSRF header

        Args:
            auth_state: 褰撳墠璁よ瘉鐘舵€併€?

        Returns:
            閲嶅缓鍚庣殑 header 鍒楄〃銆?
        """
        headers: list[tuple[str, str]] = []
        seen_keys: set[str] = set()

        for k, v in auth_state.raw_headers:
            k_lower = k.lower()

            # 鏇挎崲 Authorization
            if k_lower == "authorization" and auth_state.token_value:
                if auth_state.auth_type in ("bearer", "jwt"):
                    headers.append((k, f"Bearer {auth_state.token_value}"))
                else:
                    headers.append((k, v))
                seen_keys.add(k_lower)
                continue

            # 鏇挎崲 Cookie
            if k_lower == "cookie" and auth_state.auth_type == "cookie" and auth_state.token_value:
                headers.append((k, auth_state.token_value))
                seen_keys.add(k_lower)
                continue

            # 鏇挎崲 API Key
            if k_lower == "x-api-key" and auth_state.token_value:
                headers.append((k, auth_state.token_value))
                seen_keys.add(k_lower)
                continue

            # 鏇挎崲 Tenant
            if (
                auth_state.tenant_header
                and k_lower == auth_state.tenant_header.lower()
                and auth_state.tenant_id
            ):
                headers.append((auth_state.tenant_header, auth_state.tenant_id))
                seen_keys.add(k_lower)
                continue

            # 鏇挎崲 CSRF
            if (
                auth_state.csrf_header
                and k_lower == auth_state.csrf_header.lower()
                and auth_state.csrf_token
            ):
                headers.append((auth_state.csrf_header, auth_state.csrf_token))
                seen_keys.add(k_lower)
                continue

            # 淇濈暀鍘熷 header
            headers.append((k, v))
            seen_keys.add(k_lower)

        # 琛ュ厖鏈湪 raw_headers 涓殑鏂?header
        if auth_state.csrf_header and auth_state.csrf_token and auth_state.csrf_header.lower() not in seen_keys:
            headers.append((auth_state.csrf_header, auth_state.csrf_token))

        if auth_state.tenant_header and auth_state.tenant_id and auth_state.tenant_header.lower() not in seen_keys:
            headers.append((auth_state.tenant_header, auth_state.tenant_id))

        return headers

    def is_token_expired(self, auth_state: AuthState, *, ahead: float = 0.0) -> bool:
        """妫€鏌?token 鏄惁宸茶繃鏈熸垨鍗冲皢杩囨湡銆?

        Args:
            auth_state: 璁よ瘉鐘舵€併€?
            ahead: 鎻愬墠閲?(绉?, 濡?60 = 鎻愬墠 60 绉掑垽瀹氫负杩囨湡銆?

        Returns:
            True 濡傛灉 token 宸茶繃鏈熸垨鍗冲皢杩囨湡銆?
        """
        if auth_state.token_expiry is None:
            return False
        return time.time() + ahead >= auth_state.token_expiry

    async def _try_token_refresh(
        self,
        auth_state: AuthState,
        host: str,
        use_tls: bool,
    ) -> bool:
        """灏濊瘯 token 鍒锋柊銆?

        瀛︽湳渚濇嵁:
            - RFC 6749 搂6 鈥?OAuth 2.0 Token Refresh grant type

        绛栫暐:
            1. POST refresh_endpoint with current token
            2. 瑙ｆ瀽鍝嶅簲涓殑鏂?token
            3. 鏇存柊 auth_state.token_value
        """
        import httpx

        if not host or not auth_state.refresh_endpoint:
            return False

        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{host}{auth_state.refresh_endpoint}"

        # 鏋勫缓鍒锋柊璇锋眰 headers
        headers: dict[str, str] = {}
        for k, v in auth_state.raw_headers:
            if k.lower() not in ("content-length", "host", "content-type"):
                headers[k] = v
        headers["Content-Type"] = "application/json"

        # 鍒锋柊璇锋眰 body
        refresh_body = json.dumps({"refresh_token": auth_state.token_value}, ensure_ascii=False)

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=False
            ) as client:
                response = await client.request(
                    method=auth_state.refresh_method,
                    url=url,
                    headers=headers,
                    content=refresh_body,
                )

                if response.status_code >= 400:
                    logger.debug(
                        "Token refresh failed: HTTP %d",
                        response.status_code,
                    )
                    return False

                # 瑙ｆ瀽鏂?token
                try:
                    data = response.json()
                    new_token = (
                        data.get("access_token")
                        or data.get("token")
                        or data.get("accessToken")
                    )
                    if new_token:
                        auth_state.token_value = new_token
                        # 鏇存柊 JWT expiry (濡傛灉鏂?token 鏄?JWT)
                        jwt_payload = _decode_jwt_payload(new_token)
                        if jwt_payload and jwt_payload.get("exp"):
                            auth_state.token_expiry = float(jwt_payload["exp"]) - 60.0
                        logger.info("Token refreshed successfully")
                        return True
                except (json.JSONDecodeError, TypeError):
                    pass

        except Exception as e:
            logger.debug("Token refresh error: %s", e)

        return False

    async def _try_relogin(
        self,
        auth_state: AuthState,
        login_endpoint: str,
        username: str,
        password: str,
        host: str,
        use_tls: bool,
    ) -> bool:
        """灏濊瘯閲嶆柊鐧诲綍鑾峰彇鏂?token銆?

        瀛︽湳渚濇嵁:
            - OWASP WSTG-ATHN-02 鈥?璁よ瘉鏈哄埗娴嬭瘯

        绛栫暐:
            1. POST login_endpoint with credentials
            2. 瑙ｆ瀽鍝嶅簲涓殑 token
            3. 鏇存柊 auth_state
        """
        import httpx

        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{host}{login_endpoint}"

        headers = {"Content-Type": "application/json"}
        # 淇濈暀闈炶璇?headers (濡?User-Agent)
        for k, v in auth_state.raw_headers:
            if k.lower() not in (
                "authorization", "cookie", "x-api-key",
                "content-length", "host", "content-type",
            ):
                headers[k] = v

        login_body = json.dumps(
            {"username": username, "password": password},
            ensure_ascii=False,
        )

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=False
            ) as client:
                response = await client.post(
                    url=url,
                    headers=headers,
                    content=login_body,
                )

                if response.status_code >= 400:
                    logger.debug("Re-login failed: HTTP %d", response.status_code)
                    return False

                try:
                    data = response.json()
                    new_token = (
                        data.get("access_token")
                        or data.get("token")
                        or data.get("accessToken")
                    )
                    if new_token:
                        auth_state.token_value = new_token
                        auth_state.auth_type = "bearer"
                        jwt_payload = _decode_jwt_payload(new_token)
                        if jwt_payload:
                            auth_state.auth_type = "jwt"
                            exp = jwt_payload.get("exp")
                            if exp:
                                auth_state.token_expiry = float(exp) - 60.0
                        logger.info("Re-login successful, new token acquired")
                        return True
                except (json.JSONDecodeError, TypeError):
                    pass

        except Exception as e:
            logger.debug("Re-login error: %s", e)

        return False


def _decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """瑙ｇ爜 JWT payload (涓嶉獙绛?銆?

    瀛︽湳渚濇嵁:
        - RFC 7519 搂3 鈥?JWT 缁撴瀯: header.payload.signature
        - RFC 7519 搂4.1.4 鈥?exp (Expiration Time) claim
        - RFC 7515 搂2 鈥?涓嶉獙绛句粎瑙ｇ爜 payload 鐢ㄤ簬淇℃伅鎻愬彇

    Args:
        token: JWT token 瀛楃涓层€?

    Returns:
        payload 瀛楀吀, 鎴?None 濡傛灉涓嶆槸鏈夋晥 JWT銆?
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        # JWT payload 鏄浜屾
        payload_b64 = parts[1]
        # base64url padding 琛ラ綈
        padding_needed = 4 - len(payload_b64) % 4
        if padding_needed < 4:
            payload_b64 += _B64_PAD * padding_needed

        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)
        if isinstance(payload, dict):
            return payload
    except (ValueError, json.JSONDecodeError, Exception) as e:
        logger.debug("JWT decode failed: %s", e)

    return None

