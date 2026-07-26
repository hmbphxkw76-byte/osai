# pyrit-web-recon 自动填充 + 人工登录 + 自动接管实现计划

## Context

当前 Pipeline 在侦察 `https://student.syxy.ouchn.cn/` 时，导航后被 SSO 重定向到登录页，但后续阶段未识别登录状态，直接继续执行 `entry_discovery`，误点了登录页上的 `a.ml-auto`，导致最终未能发现聊天输入框、跳过探测交互。用户希望在 `.env` 中增加用户名/密码配置，打开目标页面后自动填充表单，由用户手动完成点击登录/滑块/拼图验证码，随后代码自动检测认证成功并接管后续侦察流程。

## Current Code Issues Diagnosed

| 问题 | 影响 | 关键位置 |
|------|------|----------|
| 登录页检测太晚 | `entry_discovery` 在 `dom_recon` 之前执行，会在登录页上误点无关元素（如运行日志中的 `a.ml-auto`） | `src/pipeline/stages/entry_discovery.py:40` 前无登录页守卫 |
| 导航后未立即等待登录 | `navigation` 阶段导航到 SSO 登录页后直接返回，后续阶段在登录页继续跑 | `src/pipeline/stages/navigation.py:44` 后无登录页处理 |
| 缺少账号密码自动填充 | 用户配置了凭据后仍需手动输入，不符合需求 | 无相关模块 |
| SSO 跨域跳转检测不健壮 | `wait_for_manual_login` 仅依赖当前页 DOM 轮询，未充分利用 URL 域变化 | `src/utils/login_waiter.py:114-120` |
| 浏览器关闭顺序不当 | `BrowserManager.close()` 未先关 page，且 Pipeline 未显式关闭浏览器/拦截器，退出时出现 Windows asyncio pipe 错误 | `src/browser_manager.py:178-186`，`main.py:252` 后无清理 |

## Implementation Plan

### 1. `.env.example`（带例外说明）

在保留 `RECON_TARGET_URL` 的基础上，新增可选凭据占位符，并显式说明这是用户明确要求的例外：

```text
# 可选：登录账号/密码。仅当同时提供时，才会在检测到登录页后自动填充。
# 点击登录/验证码仍需人工完成。注意：.env 文件已被 .gitignore 忽略。
# RECON_USERNAME=your_username
# RECON_PASSWORD=your_password
```

> 与 project_memory 的冲突处理：`.env.example` 原则上只放 `RECON_TARGET_URL`，但本次需求明确要求把用户名/密码纳入 `.env`。方案是仅在示例文件中以**注释形式**出现，不开启默认值，并在 README 中记录此例外。

### 2. `main.py`

- 在 `build_parser()` 中新增参数：
  - `--username` / `--password`
  - 默认值分别读取 `RECON_USERNAME` / `RECON_PASSWORD`
- 将 `args.username`、`args.password` 写入 `merged_config["username"]`、`merged_config["password"]`
- 在 `runner.run()` 后用 `try/finally` 显式关闭拦截器和浏览器：

```python
try:
    final_context = await runner.run(context)
finally:
    if final_context.interceptor:
        await final_context.interceptor.stop()
    if final_context.browser_manager:
        await final_context.browser_manager.close()
```

### 3. 新增 `src/auth/form_filler.py`

职责：仅自动填充账号密码，**绝不点击登录按钮或提交表单**。

```python
async def fill_login_form(page, username: str, password: str) -> Dict[str, Any]:
    # 1. 使用 LOGIN_PAGE_SELECTORS["username"] 依次尝试定位可见的用户名输入框
    # 2. 使用 LOGIN_PAGE_SELECTORS["password"] 依次尝试定位可见的密码输入框
    # 3. 分别调用 page.fill(selector, value)
    # 4. 返回 {"filled_username": bool, "filled_password": bool, "username_selector": str, "password_selector": str}
```

实现要点：
- 每个字段循环选择器池，找到第一个可见元素即停止
- 填充前可清空单引号/旧值，避免追加
- 捕获异常，单个字段失败不影响另一个字段
- 不处理验证码、不点击 submit

### 4. `src/pipeline/stages/navigation.py`

在 `browser.start()` 之后立即插入登录页检测与处理逻辑：

```python
spa_config = self._config(context, "spa_config", {})
detector = DOMDetector(page, spa_config)
is_login = await detector.is_login_page()

if is_login:
    username = self._config(context, "username") or self._spa_config(context, "username", "")
    password = self._config(context, "password") or self._spa_config(context, "password", "")

    if username and password:
        fill_result = await fill_login_form(page, username, password)
        logger.info("Auto-filled login form: %s", fill_result)

    # 只要检测到登录页就进入人工等待（无论是否提供了凭据）
    wait_result = await wait_for_manual_login(
        page,
        detector,
        timeout_ms=self._spa_config(context, "manual_login_timeout_ms", 300000),
        poll_interval_ms=self._spa_config(context, "manual_login_poll_ms", 2000),
        require_enter=self._spa_config(context, "manual_login_require_enter", False),  # 默认改为自动接管
        target_url=context.target_url,
    )
    context.config["_manual_login_wait_result"] = wait_result

    if not wait_result["login_resolved"]:
        return StageResult(success=False, message="登录未完成或超时", data=wait_result)

    # 重新检测，确认已离开登录页
    detector = DOMDetector(context.page, spa_config)
    if await detector.is_login_page():
        return StageResult(success=False, message="登录后仍在登录页", data={})
```

关键改动：
- 把登录页处理从 `dom_recon` 前移到 `navigation`
- 自动填充后进入等待，让用户手动点击登录/完成验证码
- 默认 `require_enter=False`，登录成功后自动继续

### 5. `src/pipeline/stages/entry_discovery.py`

在 `discover_chat_entry` 前增加登录页守卫，防止在登录页误点：

```python
from src.dom import DOMDetector

# 如果当前仍在登录页，跳过入口发现
detector = DOMDetector(page, self._config(context, "spa_config", {}))
if await detector.is_login_page():
    return StageResult(
        success=True,
        skipped=True,
        message="当前为登录页，跳过聊天入口发现",
        data={},
    )
```

### 6. `src/pipeline/stages/dom_recon.py`

- 若 `context.config.get("_manual_login_wait_result", {}).get("login_resolved")` 为真，说明 `navigation` 已处理过登录，直接执行 `detect_all`，不再等待
- 保留原有 `manual_login` 等待逻辑作为兜底（例如某些场景登录页在入口点击后才出现）
- `_ensure_target_page` 保持不变

### 7. `src/utils/login_waiter.py`

增强登录完成判定与提示：

1. **判定条件扩展**（满足任一即认为登录完成）：
   - 登录表单消失且检测到聊天输入框
   - 当前 URL 已回到 `target_url` 域名
   - 当前 URL 域从登录域（如 `passport.*`）跳转到其他非登录域且出现输入框
   - 用户按 Enter 确认（仅在 `require_enter=True` 时）

2. **验证码/滑块提示**：
   - 轮询时检测常见验证码容器（如 `#captcha`, `.captcha`, `.slider`, `.puzzle`, `.geetest`, `.nc-container`）
   - 若存在，打印提示“检测到验证码/滑块，请人工完成后等待系统自动继续”

3. **自动接管**：
   - `require_enter=False` 时，检测到登录完成立即返回，不再等待 Enter

4. **SSO 健壮性**：
   - 使用 `page.url` 实时获取当前 URL
   - 同时记录 `login_domain`，当域从登录域发生显著变化且页面出现聊天输入框时判定成功

### 8. `src/browser_manager.py`

优化关闭顺序，减少 Windows pipe 警告：

```python
async def close(self):
    try:
        if self._page and not self._page.is_closed():
            await self._page.close()
    except Exception:
        pass
    try:
        if self._context:
            await self._context.close()
    except Exception:
        pass
    try:
        if self._browser:
            await self._browser.close()
    except Exception:
        pass
    try:
        if self._playwright:
            await self._playwright.stop()
    except Exception:
        pass
    self._page = self._context = self._browser = self._playwright = None
    logger.info("Browser closed")
```

同时考虑：
- 在 `start()` 中保留 `page` 的引用
- 若后续发现仍有 pipe 错误，可进一步在 `main.py` 的 `finally` 中增加 `await asyncio.sleep(0.2)` 让事件循环消化残余回调

## Detailed Execution Flow

```text
credential_discovery
       ↓
authentication（根据凭据/参数决定需要人工登录）
       ↓
api_probe（Web 目标跳过）
       ↓
navigation
  ├─ 启动 BrowserManager 并导航到目标 URL
  ├─ 创建 DOMDetector，检测是否为登录页
  ├─ 若是登录页：
  │   ├─ 有 RECON_USERNAME/RECON_PASSWORD 则调用 fill_login_form 自动填充
  │   ├─ 打印提示：请人工点击登录/完成滑块验证码
  │   └─ 调用 wait_for_manual_login 等待登录完成（默认自动接管）
  └─ 登录成功后返回
       ↓
entry_discovery
  ├─ 若仍在登录页则跳过（安全守卫）
  └─ 否则发现并点击 AI 聊天入口
       ↓
dom_recon
  ├─ 若 navigation 已处理登录，直接检测 DOM
  └─ 否则按需再次进入人工登录等待
       ↓
network_interception → probe_interaction → analysis → credential_extraction → export
       ↓
main.py finally
  ├─ 停止 HTTPInterceptor
  └─ 关闭 BrowserManager
```

## Verification Steps

1. 在 `.env` 中配置：
   ```text
   RECON_TARGET_URL=https://student.syxy.ouchn.cn/
   RECON_USERNAME=你的账号
   RECON_PASSWORD=你的密码
   ```
2. 运行：
   ```bash
   python main.py --verbose
   ```
3. 观察：
   - 导航到登录页后，用户名、密码字段被自动填充
   - 终端提示“请人工点击登录/完成验证码”
   - 用户手动点击登录后，流水线自动检测到跳转并继续
   - `entry_discovery` 不再在登录页误点元素
   - `dom_recon` 检测到聊天输入框
   - `probe_interaction` 成功发送探测消息
4. 退出时检查是否仍有大量 `ValueError: I/O operation on closed pipe` 警告；预期只剩极少数可忽略的 asyncio 清理警告。

## Dependencies and Risks

- 新增 `src/auth/form_filler.py` 依赖 `src.dom.LOGIN_PAGE_SELECTORS`
- 部分 SSO 登录页的账号输入框可能是 `input[type="email"]` 或自定义 `name`，可能需要扩展 `LOGIN_PAGE_SELECTORS`
- `wait_for_manual_login` 的 `require_enter` 默认值改为 `False` 会改变现有 CLI 行为；如需保持原行为，可在 `main.py` 中新增 `--manual-login-require-enter` 默认开启，或仅在提供凭据时默认自动接管

## Critical Files for Implementation

- `D:\文档\GitHub\osai\pyrit-web-recon\main.py`
- `D:\文档\GitHub\osai\pyrit-web-recon\src\pipeline\stages\navigation.py`
- `D:\文档\GitHub\osai\pyrit-web-recon\src\pipeline\stages\entry_discovery.py`
- `D:\文档\GitHub\osai\pyrit-web-recon\src\pipeline\stages\dom_recon.py`
- `D:\文档\GitHub\osai\pyrit-web-recon\src\utils\login_waiter.py`
- `D:\文档\GitHub\osai\pyrit-web-recon\src\browser_manager.py`
- `D:\文档\GitHub\osai\pyrit-web-recon\src\auth\form_filler.py`（新增）
- `D:\文档\GitHub\osai\pyrit-web-recon\.env.example`
